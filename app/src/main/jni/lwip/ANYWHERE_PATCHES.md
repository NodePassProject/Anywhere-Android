# Anywhere Patches to lwIP

This directory holds a vendored copy of lwIP with a small number of
targeted modifications for the Anywhere VPN service's TUN-based
deployment. Every in-source modification is bracketed with

```
/* --- BEGIN Anywhere Patch: <short tag> --- */
...
/* --- END Anywhere Patch --- */
```

so the full set can be located with:

```
grep -rn "Anywhere Patch" "app/src/main/jni/lwip/src"
```

The set of patches mirrors the iOS port; see `Anywhere/Anywhere
Network Extension/lwip/ANYWHERE_PATCHES.md` for the original
discussion. Differences in deployment context are noted below.

## Deployment context

lwIP runs inside `AnywhereVpnService` as the peer TCP stack for the
local Android kernel. A proxied TCP connection flows through:

```
Android app
  │  (kernel TCP)
VpnService TUN fd  ◀─── in-memory "link", no loss / reorder / congestion
  │
LwipStack.outputPackets / lwip_bridge_input
  │
lwIP (this vendored copy)
  │  (tcp_write / tcp_recv)
LwipTcpConnection.kt
  │
ProxyConnection (VLESS / direct / …)
  │
Real internet
```

The segment between the Android kernel and lwIP is in-process memory.
It does not lose, reorder, or congest packets; the only real
bottleneck is the proxy connection and the remote server beyond it.
This asymmetry motivates the patches below.

---

## Patches

### 1. `src/core/tcp_out.c` — disable cwnd for TUN

**What:** In `tcp_output`, stop clamping the sendable window by the
congestion window. Use `pcb->snd_wnd` alone.

```c
/* before */
wnd = LWIP_MIN(pcb->snd_wnd, pcb->cwnd);

/* after */
wnd = pcb->snd_wnd;
```

**Why:** The peer is the local kernel over an in-memory flow, so cwnd
cannot legitimately indicate congestion here. Left enabled, it produces
only spurious throttles:

- **Initial slow-start ramp.** `cwnd` starts at
  `LWIP_TCP_CALC_INITIAL_CWND(mss)` and ramps through slow start up to
  `ssthresh = TCP_SND_BUF`, unnecessarily limiting the first few RTTs
  of every new connection.
- **RTO collapse** (`tcp_slowtmr`, `src/core/tcp.c`). Any spurious
  timeout — a brief `outputPackets` drain stall, a delayed app-side
  ACK, an executor scheduling hiccup — resets `cwnd = 1 · MSS` and
  halves `ssthresh`. Recovery then takes many RTTs of slow start.
- **Fast-retransmit halving** on 3 duplicate ACKs
  (`tcp_rexmit_fast`, `src/core/tcp_out.c`) — rare in TUN but not
  impossible under packet reordering.

`snd_wnd` (the app kernel's advertised receive window, scaled per
RFC 1323) remains in the expression, so peer-side flow control keeps
working.

**What is unaffected:**

- Retransmissions still fire. Both `tcp_slowtmr` (RTO) and
  `tcp_rexmit_fast` drive off `pcb->unacked` and the `TF_INFR` flag,
  not cwnd.
- All cwnd / ssthresh bookkeeping in `tcp_in.c` and `tcp_out.c` keeps
  running. It simply no longer gates output.
- `TCP_SND_BUF` and `TCP_SND_QUEUELEN` still bound the in-flight data
  held in `pcb->unsent` + `pcb->unacked`.
- Nagle, delayed ACKs, window scaling, SACK, and persist timer logic
  are unchanged.

**Upgrade notes:** When bumping the vendored lwIP version, re-apply
this one-line change. Search for

```
wnd = LWIP_MIN(pcb->snd_wnd, pcb->cwnd);
```

in `src/core/tcp_out.c` inside `tcp_output()`.

---

### 2. `src/core/tcp_in.c` — deferred SYN-ACK for outbound dial gating

**What:** Insert a hook in `tcp_listen_input`, after the new SYN_RCVD PCB is
allocated and parsed but *before* `tcp_enqueue_flags(npcb, TCP_SYN | TCP_ACK)`,
that calls back into the bridge (`lwip_bridge_handle_pre_accept(npcb)`) and
acts on its return:

```
0 (ALLOW)  → fall through to the normal SYN-ACK enqueue (legacy behavior).
1 (DEFER)  → return early. PCB stays in SYN_RCVD with empty unsent/unacked.
             Bridge later calls lwip_bridge_tcp_complete_accept(pcb) to emit
             the SYN-ACK, or lwip_bridge_tcp_reject_accept(pcb) to send RST.
2 (REJECT) → tcp_abandon(npcb, 1). RST in response to the SYN, free PCB.
```

**Why:** Without the hook, every accepted TUN connection completes the inner
3-way handshake before we know whether upstream is reachable. Subsequent
upstream connect failures then surface to the local app as a mid-stream RST,
which TLS/HTTP/speedtest clients treat as transient and retry against —
defeating routing rules and amplifying log noise. Deferring SYN-ACK lets a
connect failure be reported to the client's TCP stack as a SYN-time RST,
which `connect(2)` surfaces as `ECONNREFUSED` with no retry storm.

The Kotlin bridge picks DEFER for connections whose route is fully known at
SYN time (fake-IP, IP-CIDR with a resolved configuration), and ALLOW for
connections that need bytes from the local app before routing is decided
(SNI-sniff path).

**Interaction with `tcp_slowtmr`:** A SYN_RCVD PCB without SYN-ACK still
trips `TCP_SYN_RCVD_TIMEOUT` (default 20 s, `tcp_priv.h:129`) and is
reaped with `ERR_ABRT`. Our `TunnelConstants.handshakeTimeoutMs` is 60 s, so
without intervention lwIP would purge the PCB out from under an in-flight
upstream dial. We bump `TCP_SYN_RCVD_TIMEOUT` to 75 s in
`port/lwipopts.h` so the Kotlin handshake timer always wins. Existing
`closed`-guarded async checks in `LwipTcpConnection` already prevent
use-after-free if the order ever inverts; this is purely about clean logs.

**Interaction with `tcp_process` SYN_RCVD case:** A SYN retransmit on a
deferred PCB hits `tcp_process` `case SYN_RCVD: if (flags & TCP_SYN) … →
tcp_rexmit(pcb)`. With no segments queued, `tcp_rexmit` is a harmless
no-op, so we silently absorb client SYN retries until either complete or
reject is called.

**What is unaffected:**

- The legacy late `tcp_accept_cb` path still works when no pre-accept
  handler is registered (the hook returns ALLOW by default).
- All SYN_RCVD → ESTABLISHED bookkeeping in `tcp_process` is unchanged —
  the late accept callback fires after the client's ACK as always; in the
  deferred path it's a stub that returns `ERR_OK` because pre-accept already
  wired `tcp_arg`/`tcp_recv`/`tcp_sent`/`tcp_err`.
- ALLOW paths reach `tcp_enqueue_flags(npcb, TCP_SYN | TCP_ACK)` exactly
  as before.

**Upgrade notes:** When bumping the vendored lwIP version, re-apply this
block. Search for the second occurrence of `tcp_enqueue_flags(npcb, TCP_SYN
| TCP_ACK)` in `src/core/tcp_in.c`; it lives inside `tcp_listen_input` just
after the `LWIP_TCP_PCB_NUM_EXT_ARGS` block. Also re-check the
`TCP_SYN_RCVD_TIMEOUT` override in `port/lwipopts.h` and the `#ifndef`
guard in `src/include/lwip/priv/tcp_priv.h`.

---

### 3. `src/include/lwip/priv/tcp_priv.h` — `#ifndef`-guard timeout overrides

**What:** Wrap `TCP_FIN_WAIT_TIMEOUT` and `TCP_SYN_RCVD_TIMEOUT` in
`#ifndef` so `lwipopts.h` overrides actually take effect.

```c
/* before */
#define TCP_FIN_WAIT_TIMEOUT 20000 /* milliseconds */
#define TCP_SYN_RCVD_TIMEOUT 20000 /* milliseconds */

/* after */
#ifndef TCP_FIN_WAIT_TIMEOUT
#define TCP_FIN_WAIT_TIMEOUT 20000 /* milliseconds */
#endif
#ifndef TCP_SYN_RCVD_TIMEOUT
#define TCP_SYN_RCVD_TIMEOUT 20000 /* milliseconds */
#endif
```

**Why:** The deferred SYN-ACK patch above relies on `TCP_SYN_RCVD_TIMEOUT`
being raised above `TunnelConstants.handshakeTimeoutMs` (60 s) so the
Kotlin handshake timer fires before lwIP's `tcp_slowtmr` reaper. Without
this guard, the override in `port/lwipopts.h` is silently overwritten by
the unconditional `#define` in `tcp_priv.h`, producing a
`-Wmacro-redefined` warning and the original 20 s timeout taking effect.
Functionally the deferred path still tears down cleanly via `tcp_err` →
`handleError`, but the visible log line becomes `[TCP] lwIP aborted
connection: ERR_ABRT` instead of `[TCP] Handshake timeout during proxy
dial`.

**Upgrade notes:** Re-apply when bumping lwIP — both timeout macros lack
guards in upstream.

---

### 4. `src/include/lwip/priv/tcp_priv.h` — disable delayed ACK

**What:** Redefine the `tcp_ack` macro to always queue an immediate
ACK (`TF_ACK_NOW`) instead of the stretch-ACK pattern that ACKs every
other received segment and falls back to a 250 ms timer for the tail.

```c
/* before */
#define tcp_ack(pcb) \
  do { \
    if ((pcb)->flags & TF_ACK_DELAY) { \
      tcp_clear_flags(pcb, TF_ACK_DELAY); \
      tcp_ack_now(pcb); \
    } else { \
      tcp_set_flags(pcb, TF_ACK_DELAY); \
    } \
  } while (0)

/* after */
#define tcp_ack(pcb) tcp_set_flags(pcb, TF_ACK_NOW)
```

**Why:** The original stretch-ACK logic delays the ACK for odd-count
segment bursts by up to one `tcp_fasttmr` tick (250 ms in our build).
On the in-memory TUN flow, ACK packets cost essentially nothing — they
take the `netif_output → outputPackets → ParcelFileDescriptor.write`
path back to the Android kernel with no real link in between — while
the 250 ms tail is a direct user-visible latency tax on short flows
(HTTP GET headers, TLS handshake tail segments, single-segment
request/response).

Doubling the ACK rate on bulk upload is negligible; the cost is a few
hundred extra ~40-byte ACK packets per second at 1 MB/s upload.

**What is unaffected:**

- `tcp_ack_now` is untouched; call sites that explicitly want an
  immediate ACK still behave the same.
- `TF_ACK_DELAY` is still read by `tcp_fasttmr` (`src/core/tcp.c`) and
  still set by `tcp_send_empty_ack` as the ERR_MEM retry hook. Those
  paths keep working because they don't depend on `tcp_ack` ever
  setting the flag; they set it themselves when a send fails and rely
  on the next fasttmr tick to retry.
- Nagle on the send side and the persist timer are unrelated.

**Upgrade notes:** When bumping lwIP, re-apply. Search for
`#define tcp_ack(pcb)` in `src/include/lwip/priv/tcp_priv.h`.

---

## Non-patch customizations

The lwIP build is additionally tuned via `port/lwipopts.h`, using only
standard lwIP options (no source edits). Notable entries relevant to
the TUN deployment:

- `LWIP_TCP_CALC_INITIAL_CWND(mss) = 32 · mss` — a large initial cwnd.
  Redundant given the cwnd patch above, but harmless to keep as belt
  and suspenders.
- `TCP_WND`, `TCP_SND_BUF = 1024 · TCP_MSS` with `LWIP_WND_SCALE = 1`,
  `TCP_RCV_SCALE = 7` — high-throughput windowing.
- `CHECKSUM_CHECK_IP/TCP/UDP/ICMP/ICMP6 = 0` on input — we trust the
  packets the Android TUN interface hands us.
- `LWIP_TCP_SACK_OUT = 0` — SACK output is dead code on an in-memory
  flow with no reordering. Disabled to match iOS.
- `TCP_SYN_RCVD_TIMEOUT = 75000` — paired with patch #2 above, sets a
  backstop above `TunnelConstants.handshakeTimeoutMs` (60 s) so the
  Kotlin handshake timer always wins.
- `NO_SYS = 1`, `LWIP_CALLBACK_API = 1`, `LWIP_SINGLE_NETIF = 1` —
  single-netif, callback-driven, no OS threading layer.
- **Nagle is disabled per-PCB** in `lwip_bridge.c` via
  `tcp_nagle_disable(newpcb)` on every `tcp_accept`, for the same
  reason as the delayed-ACK patch above (small writes on an in-memory
  flow don't benefit from coalescing).

These knobs live entirely in `port/lwipopts.h` / `lwip_bridge.c`; no
edit to the vendored lwIP source is required to tune them.
