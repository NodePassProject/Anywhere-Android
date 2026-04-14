/*
 * ngtcp2_android_brutal.c — Android port of the iOS Hysteria Brutal CC.
 *
 * Mirrors Shared/QUIC/BrutalCongestionControl.swift and
 * Shared/ngtcp2/ngtcp2_swift_brutal.c. The iOS version kept its state in
 * Swift and called back through @_cdecl trampolines; that buys nothing on
 * Android where the equivalent would be JNI-from-native on every ACK/loss.
 *
 * Instead we hold the full state machine in C, keyed by the `ngtcp2_cc *`
 * we overwrote inside `conn`. A small global registry (linked list) maps
 * each `cc` pointer to its state; lookups happen on hot paths but the
 * list is tiny (one entry per active QUIC connection), so it's fine.
 *
 * The bandwidth setter writes `target_bps` under a mutex so it's safe to
 * call from an arbitrary thread. Everything else runs on the connection's
 * own thread (serialized by ngtcp2 / the Kotlin executor).
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "ngtcp2_conn.h"
#include "ngtcp2_cc.h"
#include "ngtcp2_bridge.h"

/* ----- Tunables (match Swift) -------------------------------------- */

#define BRUTAL_SLOT_COUNT        5
#define BRUTAL_SLOTS_TO_SKIP     1
#define BRUTAL_MIN_SAMPLE_COUNT  50ULL
#define BRUTAL_MAX_LOSS_RATE     0.2
#define BRUTAL_CWND_MULTIPLIER   2.0
#define BRUTAL_MIN_CWND_PACKETS  10ULL
#define BRUTAL_MIN_RTT_NS        50000000ULL   /* 50 ms */

/* ----- State ------------------------------------------------------- */

typedef struct {
    uint64_t second_mark;  /* UINT64_MAX = uninitialized */
    uint64_t ack_count;
    uint64_t loss_count;
} brutal_slot_t;

typedef struct brutal_state {
    /* Key */
    ngtcp2_cc *cc;

    /* Target send rate in bytes/sec. Written by the setter on any thread;
     * read from the CC callbacks. Guarded by `lock`. */
    uint64_t target_bps;
    pthread_mutex_t lock;

    /* Only touched from the connection's thread: */
    brutal_slot_t slots[BRUTAL_SLOT_COUNT];

    /* Intrusive list link. */
    struct brutal_state *next;
} brutal_state_t;

static pthread_mutex_t g_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static brutal_state_t *g_registry = NULL;

static brutal_state_t *registry_lookup(const ngtcp2_cc *cc) {
    pthread_mutex_lock(&g_registry_lock);
    brutal_state_t *it = g_registry;
    while (it && it->cc != cc) it = it->next;
    pthread_mutex_unlock(&g_registry_lock);
    return it;
}

static void registry_insert(brutal_state_t *s) {
    pthread_mutex_lock(&g_registry_lock);
    s->next = g_registry;
    g_registry = s;
    pthread_mutex_unlock(&g_registry_lock);
}

static brutal_state_t *registry_remove(const ngtcp2_cc *cc) {
    pthread_mutex_lock(&g_registry_lock);
    brutal_state_t **pp = &g_registry;
    while (*pp && (*pp)->cc != cc) pp = &(*pp)->next;
    brutal_state_t *found = *pp;
    if (found) *pp = found->next;
    pthread_mutex_unlock(&g_registry_lock);
    return found;
}

/* ----- Core logic (port of BrutalCongestionControl.swift) ---------- */

static int slot_index_for(brutal_state_t *s, uint64_t ts) {
    uint64_t second = ts / 1000000000ULL;
    int idx = (int)(second % BRUTAL_SLOT_COUNT);
    if (s->slots[idx].second_mark != second) {
        s->slots[idx].second_mark = second;
        s->slots[idx].ack_count = 0;
        s->slots[idx].loss_count = 0;
    }
    return idx;
}

static double observed_loss_rate(brutal_state_t *s, uint64_t ts) {
    uint64_t now = ts / 1000000000ULL;
    uint64_t total_ack = 0, total_loss = 0;
    for (int i = BRUTAL_SLOTS_TO_SKIP; i < BRUTAL_SLOT_COUNT; i++) {
        uint64_t target_second = now - (uint64_t)i;
        int idx = (int)(target_second % BRUTAL_SLOT_COUNT);
        brutal_slot_t *slot = &s->slots[idx];
        if (slot->second_mark != target_second) continue;
        total_ack += slot->ack_count;
        total_loss += slot->loss_count;
    }
    uint64_t total = total_ack + total_loss;
    if (total < BRUTAL_MIN_SAMPLE_COUNT) return 0.0;
    return (double)total_loss / (double)total;
}

static void update_cwnd(brutal_state_t *s, ngtcp2_conn_stat *cstat) {
    uint64_t target_bps;
    pthread_mutex_lock(&s->lock);
    target_bps = s->target_bps;
    pthread_mutex_unlock(&s->lock);
    if (target_bps == 0) return;

    uint64_t rtt_ns = cstat->smoothed_rtt;
    if (rtt_ns < BRUTAL_MIN_RTT_NS) rtt_ns = BRUTAL_MIN_RTT_NS;
    uint64_t mss = (uint64_t)cstat->max_tx_udp_payload_size;
    if (mss == 0) mss = 1;

    double loss_rate = observed_loss_rate(s, cstat->first_rtt_sample_ts + rtt_ns);
    if (loss_rate < 0.0) loss_rate = 0.0;
    if (loss_rate > BRUTAL_MAX_LOSS_RATE) loss_rate = BRUTAL_MAX_LOSS_RATE;

    double effective_bps =
        (double)target_bps / (1.0 - loss_rate) * BRUTAL_CWND_MULTIPLIER;

    double cwnd_bytes = effective_bps * (double)rtt_ns / 1e9;
    uint64_t min_cwnd = BRUTAL_MIN_CWND_PACKETS * mss;
    uint64_t cwnd = (uint64_t)cwnd_bytes;
    if (cwnd < min_cwnd) cwnd = min_cwnd;

    uint64_t pacing_interval_m;
    if (effective_bps >= 1.0) {
        double seconds = (double)mss / effective_bps;
        double nanos = seconds * 1e9;
        pacing_interval_m = (uint64_t)(nanos * 1024.0);
    } else {
        pacing_interval_m = 0;  /* library default pacing */
    }

    cstat->cwnd = cwnd;
    cstat->pacing_interval_m = pacing_interval_m;
}

/* ----- ngtcp2 callbacks ------------------------------------------- */

static void brutal_on_pkt_acked(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                                const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts) {
    (void)pkt;
    brutal_state_t *s = registry_lookup(cc);
    if (!s || !cstat) return;
    int idx = slot_index_for(s, ts);
    s->slots[idx].ack_count += 1;
    update_cwnd(s, cstat);
}

static void brutal_on_pkt_lost(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                               const ngtcp2_cc_pkt *pkt, ngtcp2_tstamp ts) {
    (void)pkt;
    brutal_state_t *s = registry_lookup(cc);
    if (!s || !cstat) return;
    int idx = slot_index_for(s, ts);
    s->slots[idx].loss_count += 1;
    update_cwnd(s, cstat);
}

static void brutal_on_ack_recv(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                               const ngtcp2_cc_ack *ack, ngtcp2_tstamp ts) {
    (void)ack; (void)ts;
    brutal_state_t *s = registry_lookup(cc);
    if (!s || !cstat) return;
    update_cwnd(s, cstat);
}

static void brutal_on_pkt_sent(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                               const ngtcp2_cc_pkt *pkt) {
    (void)pkt;
    brutal_state_t *s = registry_lookup(cc);
    if (!s || !cstat) return;
    update_cwnd(s, cstat);
}

static void brutal_reset(ngtcp2_cc *cc, ngtcp2_conn_stat *cstat,
                         ngtcp2_tstamp ts) {
    (void)ts;
    brutal_state_t *s = registry_lookup(cc);
    if (!s) return;
    for (int i = 0; i < BRUTAL_SLOT_COUNT; i++) {
        s->slots[i].second_mark = UINT64_MAX;
        s->slots[i].ack_count = 0;
        s->slots[i].loss_count = 0;
    }
    if (cstat) update_cwnd(s, cstat);
}

/* ----- Public install / update / remove ---------------------------- */

/* Overwrites `conn->cc` callbacks with the Brutal trampolines, and
 * installs a fresh state struct keyed by the `ngtcp2_cc *`. Returns the
 * `ngtcp2_cc *` on success (use as the ccPointer handle), or NULL. */
ngtcp2_cc *ngtcp2_android_install_brutal(ngtcp2_conn *conn, uint64_t initial_bps) {
    if (!conn) return NULL;
    ngtcp2_cc *cc = &conn->cc;

    brutal_state_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->cc = cc;
    s->target_bps = initial_bps;
    pthread_mutex_init(&s->lock, NULL);
    for (int i = 0; i < BRUTAL_SLOT_COUNT; i++) {
        s->slots[i].second_mark = UINT64_MAX;
    }

    registry_insert(s);

    cc->on_pkt_acked = brutal_on_pkt_acked;
    cc->on_pkt_lost = brutal_on_pkt_lost;
    cc->on_ack_recv = brutal_on_ack_recv;
    cc->on_pkt_sent = brutal_on_pkt_sent;
    cc->reset = brutal_reset;
    /* Brutal doesn't use congestion_event, on_spurious_congestion, or
     * on_persistent_congestion — ngtcp2_cc.h permits NULL. */
    cc->congestion_event = NULL;
    cc->on_spurious_congestion = NULL;
    cc->on_persistent_congestion = NULL;

    return cc;
}

void ngtcp2_android_set_brutal_bandwidth(ngtcp2_cc *cc, uint64_t bps) {
    if (!cc) return;
    brutal_state_t *s = registry_lookup(cc);
    if (!s) return;
    pthread_mutex_lock(&s->lock);
    s->target_bps = bps;
    pthread_mutex_unlock(&s->lock);
}

void ngtcp2_android_remove_brutal(ngtcp2_cc *cc) {
    if (!cc) return;
    brutal_state_t *s = registry_remove(cc);
    if (!s) return;
    pthread_mutex_destroy(&s->lock);
    free(s);
}
