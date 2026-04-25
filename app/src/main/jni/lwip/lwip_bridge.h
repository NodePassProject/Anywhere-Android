#ifndef LWIP_BRIDGE_H
#define LWIP_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

/* --- Callback types (implemented in Swift with @convention(c)) --- */

/* Netif output: lwIP wants to send an IP packet back to the TUN interface */
typedef void (*lwip_output_fn)(const void *data, int len, int is_ipv6);

/* TCP accept: new TCP connection accepted (returns opaque pointer stored as PCB arg)
 * IP addresses are raw bytes: 4 bytes for IPv4, 16 bytes for IPv6
 *
 * Used for the legacy "send SYN-ACK first, then accept" path. Most callers
 * should register a pre-accept callback instead — see lwip_tcp_pre_accept_fn. */
typedef void *(*lwip_tcp_accept_fn)(const void *src_ip, uint16_t src_port,
                                     const void *dst_ip, uint16_t dst_port,
                                     int is_ipv6, void *pcb);

/* TCP pre-accept: fired in tcp_listen_input as soon as a new SYN_RCVD PCB
 * has been set up, *before* SYN-ACK is enqueued. The callback returns a
 * decision via *out_decision:
 *   0 (ALLOW)  — proceed with normal SYN-ACK enqueue. *out_conn must be set
 *                if the caller wants the late tcp_accept callback to succeed.
 *   1 (DEFER)  — do not send SYN-ACK; the PCB stays in SYN_RCVD until the
 *                bridge calls lwip_bridge_tcp_complete_accept(pcb) (success)
 *                or lwip_bridge_tcp_reject_accept(pcb) (failure).
 *                *out_conn must be set so tcp_recv/tcp_sent/tcp_err can be
 *                wired through.
 *   2 (REJECT) — abandon the PCB with RST immediately. *out_conn ignored.
 *
 * Address bytes follow the same layout as lwip_tcp_accept_fn. */
typedef void (*lwip_tcp_pre_accept_fn)(const void *src_ip, uint16_t src_port,
                                        const void *dst_ip, uint16_t dst_port,
                                        int is_ipv6, void *pcb,
                                        int *out_decision, void **out_conn);

/* TCP recv: data received on a TCP connection */
typedef void (*lwip_tcp_recv_fn)(void *conn, const void *data, int len);

/* TCP sent: send buffer space freed (bytes acknowledged) */
typedef void (*lwip_tcp_sent_fn)(void *conn, uint16_t len);

/* TCP err: TCP error or connection aborted */
typedef void (*lwip_tcp_err_fn)(void *conn, int err);

/* UDP recv: UDP datagram received
 * IP addresses are raw bytes: 4 bytes for IPv4, 16 bytes for IPv6 */
typedef void (*lwip_udp_recv_fn)(const void *src_ip, uint16_t src_port,
                                  const void *dst_ip, uint16_t dst_port,
                                  int is_ipv6, const void *data, int len);

/* --- Callback registration --- */
void lwip_bridge_set_output_fn(lwip_output_fn fn);
void lwip_bridge_set_tcp_accept_fn(lwip_tcp_accept_fn fn);
void lwip_bridge_set_tcp_pre_accept_fn(lwip_tcp_pre_accept_fn fn);
void lwip_bridge_set_tcp_recv_fn(lwip_tcp_recv_fn fn);
void lwip_bridge_set_tcp_sent_fn(lwip_tcp_sent_fn fn);
void lwip_bridge_set_tcp_err_fn(lwip_tcp_err_fn fn);
void lwip_bridge_set_udp_recv_fn(lwip_udp_recv_fn fn);

/* --- Lifecycle --- */
void lwip_bridge_init(void);
void lwip_bridge_shutdown(void);

/* Abort every active TCP PCB and clear TIME_WAIT, keeping the netif and
 * listeners intact. Used on device wake to invalidate outbound proxy
 * sockets the kernel killed during sleep without a full stack rebuild. */
void lwip_bridge_abort_all_tcp(void);

/* --- Packet input (from TUN) --- */
void lwip_bridge_input(const void *data, int len);

/* --- TCP operations (called from Kotlin on lwipExecutor) --- */
int  lwip_bridge_tcp_write(void *pcb, const void *data, uint16_t len);
void lwip_bridge_tcp_output(void *pcb);
void lwip_bridge_tcp_recved(void *pcb, uint16_t len);
void lwip_bridge_tcp_close(void *pcb);
void lwip_bridge_tcp_abort(void *pcb);
int  lwip_bridge_tcp_sndbuf(void *pcb);
int  lwip_bridge_tcp_snd_queuelen(void *pcb);

/* --- Deferred-accept completion (called from Kotlin after pre-accept DEFER) ---
 *
 * Exactly one of these must be called per deferred PCB:
 *   complete_accept — upstream is up; enqueue SYN-ACK and let the inner
 *                     handshake finish.
 *   reject_accept   — upstream failed; send RST in response to the SYN so
 *                     the local app's connect(2) returns ECONNREFUSED. */
void lwip_bridge_tcp_complete_accept(void *pcb);
void lwip_bridge_tcp_reject_accept(void *pcb);

/* --- UDP operations ---
 * IP addresses are raw bytes: 4 bytes for IPv4, 16 bytes for IPv6 */
void lwip_bridge_udp_sendto(const void *src_ip_bytes, uint16_t src_port,
                             const void *dst_ip_bytes, uint16_t dst_port,
                             int is_ipv6,
                             const void *data, int len);

/* --- Timer --- */
void lwip_bridge_check_timeouts(void);

/* --- IP address utility --- */

/// Convert raw IP address bytes to a null-terminated string.
/// @param addr Raw IP bytes (4 for IPv4, 16 for IPv6)
/// @param is_ipv6 Non-zero for IPv6
/// @param out Output buffer (must be >= 46 bytes / INET6_ADDRSTRLEN)
/// @param out_len Size of output buffer
/// @return Pointer to out on success, NULL on failure
const char *lwip_ip_to_string(const void *addr, int is_ipv6,
                               char *out, size_t out_len);

#endif /* LWIP_BRIDGE_H */
