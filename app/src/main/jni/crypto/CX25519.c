/*
 * CX25519.c
 *
 * Portable X25519 Diffie-Hellman (RFC 7748).
 *
 * Based on the widely-used curve25519-donna implementation approach.
 * All arithmetic is in GF(2^255 - 19) using 64-bit limbs.
 */

#include "CX25519.h"
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

/* ========================================================================== */
/* Field element: 5 limbs of 51 bits each (fits in uint64_t)                  */
/* ========================================================================== */

typedef uint64_t fe[5];

static const uint64_t MASK51 = (1ULL << 51) - 1;

static inline uint64_t load64_le(const uint8_t *p) {
    return (uint64_t)p[0]       | ((uint64_t)p[1] << 8)  | ((uint64_t)p[2] << 16) |
           ((uint64_t)p[3] << 24) | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) |
           ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void store64_le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

static void fe_frombytes(fe out, const uint8_t s[32]) {
    uint64_t r0 = load64_le(s);
    uint64_t r1 = load64_le(s + 8);
    uint64_t r2 = load64_le(s + 16);
    uint64_t r3 = load64_le(s + 24);

    out[0] =  r0                        & MASK51;  /* bits   0 -  50 */
    out[1] = ((r0 >> 51) | (r1 << 13))  & MASK51;  /* bits  51 - 101 */
    out[2] = ((r1 >> 38) | (r2 << 26))  & MASK51;  /* bits 102 - 152 */
    out[3] = ((r2 >> 25) | (r3 << 39))  & MASK51;  /* bits 153 - 203 */
    out[4] =  (r3 >> 12)                & MASK51;  /* bits 204 - 254 */
}

static void fe_tobytes(uint8_t s[32], const fe h) {
    /* Reduce modulo 2^255-19 */
    uint64_t t[5];
    memcpy(t, h, sizeof(t));

    /* Carry chain */
    uint64_t c;
    c = t[0] >> 51; t[1] += c; t[0] &= MASK51;
    c = t[1] >> 51; t[2] += c; t[1] &= MASK51;
    c = t[2] >> 51; t[3] += c; t[2] &= MASK51;
    c = t[3] >> 51; t[4] += c; t[3] &= MASK51;
    c = t[4] >> 51; t[0] += c * 19; t[4] &= MASK51;
    /* Second pass */
    c = t[0] >> 51; t[1] += c; t[0] &= MASK51;
    c = t[1] >> 51; t[2] += c; t[1] &= MASK51;
    c = t[2] >> 51; t[3] += c; t[2] &= MASK51;
    c = t[3] >> 51; t[4] += c; t[3] &= MASK51;
    c = t[4] >> 51; t[0] += c * 19; t[4] &= MASK51;

    /* Compute t - p; if t >= p, use t - p */
    uint64_t d[5];
    d[0] = t[0] + 19;
    c = d[0] >> 51; d[0] &= MASK51;
    d[1] = t[1] + c;
    c = d[1] >> 51; d[1] &= MASK51;
    d[2] = t[2] + c;
    c = d[2] >> 51; d[2] &= MASK51;
    d[3] = t[3] + c;
    c = d[3] >> 51; d[3] &= MASK51;
    d[4] = t[4] + c - (1ULL << 51);

    /* If d[4] has bit 63 set, t < p, keep t; else use d */
    uint64_t mask = ~(d[4] >> 63) + 1;
    t[0] = (t[0] & mask) | (d[0] & ~mask);
    t[1] = (t[1] & mask) | (d[1] & ~mask);
    t[2] = (t[2] & mask) | (d[2] & ~mask);
    t[3] = (t[3] & mask) | (d[3] & ~mask);
    t[4] = (t[4] & mask) | (d[4] & ~mask);

    /* Pack 5 × 51-bit limbs into 4 × 64-bit LE words */
    uint64_t r0 = t[0] | (t[1] << 51);
    uint64_t r1 = (t[1] >> 13) | (t[2] << 38);
    uint64_t r2 = (t[2] >> 26) | (t[3] << 25);
    uint64_t r3 = (t[3] >> 39) | (t[4] << 12);

    store64_le(s,      r0);
    store64_le(s + 8,  r1);
    store64_le(s + 16, r2);
    store64_le(s + 24, r3);
}

/* ========================================================================== */
/* Field arithmetic                                                           */
/* ========================================================================== */

static void fe_copy(fe out, const fe a) {
    memcpy(out, a, 5 * sizeof(uint64_t));
}

static void fe_add(fe out, const fe a, const fe b) {
    out[0] = a[0] + b[0];
    out[1] = a[1] + b[1];
    out[2] = a[2] + b[2];
    out[3] = a[3] + b[3];
    out[4] = a[4] + b[4];
}

static void fe_sub(fe out, const fe a, const fe b) {
    /* Add 2*p to avoid underflow before subtraction */
    out[0] = (a[0] + 0xFFFFFFFFFFFDA) - b[0];
    out[1] = (a[1] + 0xFFFFFFFFFFFFE) - b[1];
    out[2] = (a[2] + 0xFFFFFFFFFFFFE) - b[2];
    out[3] = (a[3] + 0xFFFFFFFFFFFFE) - b[3];
    out[4] = (a[4] + 0xFFFFFFFFFFFFE) - b[4];
}

static inline __uint128_t mul64(uint64_t a, uint64_t b) {
    return (__uint128_t)a * b;
}

static void fe_mul(fe out, const fe a, const fe b) {
    __uint128_t t0, t1, t2, t3, t4;
    uint64_t b1_19 = b[1] * 19;
    uint64_t b2_19 = b[2] * 19;
    uint64_t b3_19 = b[3] * 19;
    uint64_t b4_19 = b[4] * 19;

    t0 = mul64(a[0], b[0]) + mul64(a[1], b4_19) + mul64(a[2], b3_19) +
         mul64(a[3], b2_19) + mul64(a[4], b1_19);
    t1 = mul64(a[0], b[1]) + mul64(a[1], b[0]) + mul64(a[2], b4_19) +
         mul64(a[3], b3_19) + mul64(a[4], b2_19);
    t2 = mul64(a[0], b[2]) + mul64(a[1], b[1]) + mul64(a[2], b[0]) +
         mul64(a[3], b4_19) + mul64(a[4], b3_19);
    t3 = mul64(a[0], b[3]) + mul64(a[1], b[2]) + mul64(a[2], b[1]) +
         mul64(a[3], b[0]) + mul64(a[4], b4_19);
    t4 = mul64(a[0], b[4]) + mul64(a[1], b[3]) + mul64(a[2], b[2]) +
         mul64(a[3], b[1]) + mul64(a[4], b[0]);

    uint64_t c;
    out[0] = (uint64_t)t0 & MASK51; c = (uint64_t)(t0 >> 51);
    t1 += c;
    out[1] = (uint64_t)t1 & MASK51; c = (uint64_t)(t1 >> 51);
    t2 += c;
    out[2] = (uint64_t)t2 & MASK51; c = (uint64_t)(t2 >> 51);
    t3 += c;
    out[3] = (uint64_t)t3 & MASK51; c = (uint64_t)(t3 >> 51);
    t4 += c;
    out[4] = (uint64_t)t4 & MASK51; c = (uint64_t)(t4 >> 51);
    out[0] += c * 19;
    c = out[0] >> 51; out[0] &= MASK51;
    out[1] += c;
}

static void fe_sq(fe out, const fe a) {
    fe_mul(out, a, a);
}

static void fe_mul_a24(fe out, const fe a) {
    /* a24 = (A - 2) / 4 = (486662 - 2) / 4 = 121665 for curve25519 */
    __uint128_t t0 = mul64(a[0], 121665);
    __uint128_t t1 = mul64(a[1], 121665);
    __uint128_t t2 = mul64(a[2], 121665);
    __uint128_t t3 = mul64(a[3], 121665);
    __uint128_t t4 = mul64(a[4], 121665);

    uint64_t c;
    out[0] = (uint64_t)t0 & MASK51; c = (uint64_t)(t0 >> 51);
    t1 += c;
    out[1] = (uint64_t)t1 & MASK51; c = (uint64_t)(t1 >> 51);
    t2 += c;
    out[2] = (uint64_t)t2 & MASK51; c = (uint64_t)(t2 >> 51);
    t3 += c;
    out[3] = (uint64_t)t3 & MASK51; c = (uint64_t)(t3 >> 51);
    t4 += c;
    out[4] = (uint64_t)t4 & MASK51; c = (uint64_t)(t4 >> 51);
    out[0] += c * 19;
    c = out[0] >> 51; out[0] &= MASK51;
    out[1] += c;
}

/* ========================================================================== */
/* Modular inversion via Fermat's little theorem: a^(p-2) mod p               */
/* p - 2 = 2^255 - 21                                                        */
/* ========================================================================== */

static void fe_invert(fe out, const fe z) {
    fe t0, t1, t2, t3;
    int i;

    /* z^2 */
    fe_sq(t0, z);
    /* z^4 */
    fe_sq(t1, t0);
    /* z^8 */
    fe_sq(t1, t1);
    /* z^9 = z^8 * z */
    fe_mul(t1, t1, z);
    /* z^11 = z^9 * z^2 */
    fe_mul(t0, t0, t1);
    /* z^22 */
    fe_sq(t2, t0);
    /* z^31 = z^22 * z^9 */
    fe_mul(t1, t1, t2);
    /* z^2^5 */
    fe_sq(t2, t1);
    for (i = 1; i < 5; i++) fe_sq(t2, t2);
    /* z^2^5 * z^31 = z^(2^10 - 1) */
    fe_mul(t1, t2, t1);
    /* z^(2^20 - 1) */
    fe_sq(t2, t1);
    for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    /* z^(2^40 - 1) */
    fe_sq(t3, t2);
    for (i = 1; i < 20; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    /* z^(2^50 - 1) */
    fe_sq(t2, t2);
    for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    /* z^(2^100 - 1) */
    fe_sq(t2, t1);
    for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    /* z^(2^200 - 1) */
    fe_sq(t3, t2);
    for (i = 1; i < 100; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    /* z^(2^250 - 1) */
    fe_sq(t2, t2);
    for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    /* z^(2^255 - 21) */
    fe_sq(t1, t1);
    fe_sq(t1, t1);
    fe_sq(t1, t1);
    fe_sq(t1, t1);
    fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

/* ========================================================================== */
/* X25519 scalar multiplication (Montgomery ladder)                           */
/* ========================================================================== */

static void x25519_scalarmult(uint8_t out[32], const uint8_t scalar[32],
                               const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    /* Clamp (already done for private keys, but safe to repeat) */
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    fe x1, x2, z2, x3, z3, tmp0, tmp1;
    fe_frombytes(x1, point);

    /* x2 = 1, z2 = 0 */
    memset(x2, 0, sizeof(fe)); x2[0] = 1;
    memset(z2, 0, sizeof(fe));
    /* x3 = x1, z3 = 1 */
    fe_copy(x3, x1);
    memset(z3, 0, sizeof(fe)); z3[0] = 1;

    int swap = 0;

    for (int pos = 254; pos >= 0; pos--) {
        int b = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= b;

        /* Conditional swap */
        for (int j = 0; j < 5; j++) {
            uint64_t mask = (uint64_t)0 - (uint64_t)swap;
            uint64_t t = mask & (x2[j] ^ x3[j]);
            x2[j] ^= t;
            x3[j] ^= t;
            t = mask & (z2[j] ^ z3[j]);
            z2[j] ^= t;
            z3[j] ^= t;
        }
        swap = b;

        /* Montgomery ladder step */
        fe a, aa, b_fe, bb, e_fe, c, d, da, cb;

        fe_add(a, x2, z2);
        fe_sq(aa, a);
        fe_sub(b_fe, x2, z2);
        fe_sq(bb, b_fe);
        fe_sub(e_fe, aa, bb);
        fe_add(c, x3, z3);
        fe_sub(d, x3, z3);
        fe_mul(da, d, a);
        fe_mul(cb, c, b_fe);

        fe_add(tmp0, da, cb);
        fe_sq(x3, tmp0);
        fe_sub(tmp1, da, cb);
        fe_sq(tmp1, tmp1);
        fe_mul(z3, tmp1, x1);

        fe_mul(x2, aa, bb);
        fe_mul_a24(tmp0, e_fe);
        fe_add(tmp0, tmp0, aa);
        fe_mul(z2, e_fe, tmp0);
    }

    /* Final conditional swap */
    for (int j = 0; j < 5; j++) {
        uint64_t mask = (uint64_t)0 - (uint64_t)swap;
        uint64_t t = mask & (x2[j] ^ x3[j]);
        x2[j] ^= t;
        x3[j] ^= t;
        t = mask & (z2[j] ^ z3[j]);
        z2[j] ^= t;
        z3[j] ^= t;
    }

    /* out = x2 * z2^(-1) */
    fe_invert(tmp0, z2);
    fe_mul(tmp1, x2, tmp0);
    fe_tobytes(out, tmp1);
}

/* ========================================================================== */
/* The base point for X25519 (u = 9)                                          */
/* ========================================================================== */

static const uint8_t x25519_basepoint[32] = { 9 };

/* ========================================================================== */
/* Secure random bytes from /dev/urandom                                      */
/* ========================================================================== */

static int secure_random(uint8_t *buf, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) { close(fd); return -1; }
        total += (size_t)n;
    }
    close(fd);
    return 0;
}

/* ========================================================================== */
/* Public API                                                                 */
/* ========================================================================== */

void x25519_generate_keypair(uint8_t public_key[32], uint8_t private_key[32]) {
    secure_random(private_key, 32);
    /* Clamp per RFC 7748 */
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    /* public_key = scalar_mult(private_key, basepoint) */
    x25519_scalarmult(public_key, private_key, x25519_basepoint);
}

int x25519_key_agreement(uint8_t shared_secret[32],
                          const uint8_t private_key[32],
                          const uint8_t peer_public_key[32]) {
    x25519_scalarmult(shared_secret, private_key, peer_public_key);
    /* Check for all-zero output (low-order point) */
    uint8_t zero = 0;
    for (int i = 0; i < 32; i++) zero |= shared_secret[i];
    return zero ? 0 : -1;
}
