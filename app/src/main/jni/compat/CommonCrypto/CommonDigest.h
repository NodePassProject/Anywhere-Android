/*
 * CommonDigest.h — CommonCrypto compatibility shim for Android NDK.
 *
 * Provides SHA-256 and SHA-384 using portable C implementations
 * so that CTLSKeyDerivation.c can compile unchanged.
 */

#ifndef COMMONDIGEST_H_COMPAT
#define COMMONDIGEST_H_COMPAT

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef uint32_t CC_LONG;

#define CC_SHA256_DIGEST_LENGTH 32
#define CC_SHA384_DIGEST_LENGTH 48

/* --- SHA-256 --- */

typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buffer[64];
} CC_SHA256_CTX;

static inline uint32_t _sha256_rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t _sha256_ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
static inline uint32_t _sha256_maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t _sha256_S0(uint32_t x) { return _sha256_rotr(x, 2) ^ _sha256_rotr(x, 13) ^ _sha256_rotr(x, 22); }
static inline uint32_t _sha256_S1(uint32_t x) { return _sha256_rotr(x, 6) ^ _sha256_rotr(x, 11) ^ _sha256_rotr(x, 25); }
static inline uint32_t _sha256_s0(uint32_t x) { return _sha256_rotr(x, 7) ^ _sha256_rotr(x, 18) ^ (x >> 3); }
static inline uint32_t _sha256_s1(uint32_t x) { return _sha256_rotr(x, 17) ^ _sha256_rotr(x, 19) ^ (x >> 10); }

static const uint32_t _sha256_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t _sha256_be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static inline void _sha256_be32_put(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

static inline void _sha256_transform(CC_SHA256_CTX *ctx, const uint8_t *block) {
    uint32_t W[64], a, b, c, d, e, f, g, h;
    for (int i = 0; i < 16; i++) W[i] = _sha256_be32(block + i * 4);
    for (int i = 16; i < 64; i++) W[i] = _sha256_s1(W[i-2]) + W[i-7] + _sha256_s0(W[i-15]) + W[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + _sha256_S1(e) + _sha256_ch(e,f,g) + _sha256_K[i] + W[i];
        uint32_t t2 = _sha256_S0(a) + _sha256_maj(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static inline int CC_SHA256_Init(CC_SHA256_CTX *ctx) {
    ctx->state[0]=0x6a09e667; ctx->state[1]=0xbb67ae85;
    ctx->state[2]=0x3c6ef372; ctx->state[3]=0xa54ff53a;
    ctx->state[4]=0x510e527f; ctx->state[5]=0x9b05688c;
    ctx->state[6]=0x1f83d9ab; ctx->state[7]=0x5be0cd19;
    ctx->count = 0;
    return 1;
}

static inline int CC_SHA256_Update(CC_SHA256_CTX *ctx, const void *data, CC_LONG len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t buffered = (size_t)(ctx->count % 64);
    ctx->count += len;
    if (buffered + len < 64) { memcpy(ctx->buffer + buffered, p, len); return 1; }
    if (buffered > 0) {
        size_t fill = 64 - buffered;
        memcpy(ctx->buffer + buffered, p, fill);
        _sha256_transform(ctx, ctx->buffer);
        p += fill; len -= (CC_LONG)fill;
    }
    while (len >= 64) { _sha256_transform(ctx, p); p += 64; len -= 64; }
    if (len > 0) memcpy(ctx->buffer, p, len);
    return 1;
}

static inline int CC_SHA256_Final(uint8_t *md, CC_SHA256_CTX *ctx) {
    uint8_t pad[64] = {0x80};
    size_t buffered = (size_t)(ctx->count % 64);
    size_t padlen = (buffered < 56) ? (56 - buffered) : (120 - buffered);
    uint64_t bits = ctx->count * 8;
    uint8_t lenblock[8];
    for (int i = 7; i >= 0; i--) { lenblock[i] = (uint8_t)bits; bits >>= 8; }
    CC_SHA256_Update(ctx, pad, (CC_LONG)padlen);
    CC_SHA256_Update(ctx, lenblock, 8);
    for (int i = 0; i < 8; i++) _sha256_be32_put(md + i * 4, ctx->state[i]);
    return 1;
}

static inline unsigned char *CC_SHA256(const void *data, CC_LONG len, unsigned char *md) {
    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);
    CC_SHA256_Update(&ctx, data, len);
    CC_SHA256_Final(md, &ctx);
    return md;
}

/* --- SHA-384 (uses SHA-512 internals) --- */

typedef struct {
    uint64_t state[8];
    uint64_t count;
    uint8_t  buffer[128];
} CC_SHA512_CTX;

typedef CC_SHA512_CTX CC_SHA384_CTX;

static inline uint64_t _sha512_rotr(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }
static inline uint64_t _sha512_ch(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (~x & z); }
static inline uint64_t _sha512_maj(uint64_t x, uint64_t y, uint64_t z) { return (x & y) ^ (x & z) ^ (y & z); }
static inline uint64_t _sha512_S0(uint64_t x) { return _sha512_rotr(x,28) ^ _sha512_rotr(x,34) ^ _sha512_rotr(x,39); }
static inline uint64_t _sha512_S1(uint64_t x) { return _sha512_rotr(x,14) ^ _sha512_rotr(x,18) ^ _sha512_rotr(x,41); }
static inline uint64_t _sha512_s0(uint64_t x) { return _sha512_rotr(x,1) ^ _sha512_rotr(x,8) ^ (x >> 7); }
static inline uint64_t _sha512_s1(uint64_t x) { return _sha512_rotr(x,19) ^ _sha512_rotr(x,61) ^ (x >> 6); }

static const uint64_t _sha512_K[80] = {
    0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
    0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
    0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
    0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static inline uint64_t _sha512_be64(const uint8_t *p) {
    return ((uint64_t)p[0]<<56)|((uint64_t)p[1]<<48)|((uint64_t)p[2]<<40)|((uint64_t)p[3]<<32)|
           ((uint64_t)p[4]<<24)|((uint64_t)p[5]<<16)|((uint64_t)p[6]<<8)|p[7];
}

static inline void _sha512_be64_put(uint8_t *p, uint64_t v) {
    p[0]=(uint8_t)(v>>56); p[1]=(uint8_t)(v>>48); p[2]=(uint8_t)(v>>40); p[3]=(uint8_t)(v>>32);
    p[4]=(uint8_t)(v>>24); p[5]=(uint8_t)(v>>16); p[6]=(uint8_t)(v>>8); p[7]=(uint8_t)v;
}

static inline void _sha512_transform(CC_SHA512_CTX *ctx, const uint8_t *block) {
    uint64_t W[80], a, b, c, d, e, f, g, h;
    for (int i = 0; i < 16; i++) W[i] = _sha512_be64(block + i * 8);
    for (int i = 16; i < 80; i++) W[i] = _sha512_s1(W[i-2]) + W[i-7] + _sha512_s0(W[i-15]) + W[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (int i = 0; i < 80; i++) {
        uint64_t t1 = h + _sha512_S1(e) + _sha512_ch(e,f,g) + _sha512_K[i] + W[i];
        uint64_t t2 = _sha512_S0(a) + _sha512_maj(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

static inline int CC_SHA512_Init(CC_SHA512_CTX *ctx) {
    ctx->state[0]=0x6a09e667f3bcc908ULL; ctx->state[1]=0xbb67ae8584caa73bULL;
    ctx->state[2]=0x3c6ef372fe94f82bULL; ctx->state[3]=0xa54ff53a5f1d36f1ULL;
    ctx->state[4]=0x510e527fade682d1ULL; ctx->state[5]=0x9b05688c2b3e6c1fULL;
    ctx->state[6]=0x1f83d9abfb41bd6bULL; ctx->state[7]=0x5be0cd19137e2179ULL;
    ctx->count = 0;
    return 1;
}

static inline int CC_SHA384_Init(CC_SHA384_CTX *ctx) {
    ctx->state[0]=0xcbbb9d5dc1059ed8ULL; ctx->state[1]=0x629a292a367cd507ULL;
    ctx->state[2]=0x9159015a3070dd17ULL; ctx->state[3]=0x152fecd8f70e5939ULL;
    ctx->state[4]=0x67332667ffc00b31ULL; ctx->state[5]=0x8eb44a8768581511ULL;
    ctx->state[6]=0xdb0c2e0d64f98fa7ULL; ctx->state[7]=0x47b5481dbefa4fa4ULL;
    ctx->count = 0;
    return 1;
}

static inline int CC_SHA512_Update(CC_SHA512_CTX *ctx, const void *data, CC_LONG len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t buffered = (size_t)(ctx->count % 128);
    ctx->count += len;
    if (buffered + len < 128) { memcpy(ctx->buffer + buffered, p, len); return 1; }
    if (buffered > 0) {
        size_t fill = 128 - buffered;
        memcpy(ctx->buffer + buffered, p, fill);
        _sha512_transform(ctx, ctx->buffer);
        p += fill; len -= (CC_LONG)fill;
    }
    while (len >= 128) { _sha512_transform(ctx, p); p += 128; len -= 128; }
    if (len > 0) memcpy(ctx->buffer, p, len);
    return 1;
}

#define CC_SHA384_Update CC_SHA512_Update

static inline int CC_SHA512_Final(uint8_t *md, CC_SHA512_CTX *ctx) {
    uint8_t pad[128];
    memset(pad, 0, sizeof(pad));
    pad[0] = 0x80;
    size_t buffered = (size_t)(ctx->count % 128);
    size_t padlen = (buffered < 112) ? (112 - buffered) : (240 - buffered);
    uint64_t bits = ctx->count * 8;
    uint8_t lenblock[16];
    memset(lenblock, 0, 8); /* high 64 bits = 0 for messages < 2^64 bits */
    _sha512_be64_put(lenblock + 8, bits);
    CC_SHA512_Update(ctx, pad, (CC_LONG)padlen);
    CC_SHA512_Update(ctx, lenblock, 16);
    for (int i = 0; i < 8; i++) _sha512_be64_put(md + i * 8, ctx->state[i]);
    return 1;
}

static inline int CC_SHA384_Final(uint8_t *md, CC_SHA384_CTX *ctx) {
    uint8_t full[64];
    CC_SHA512_Final(full, ctx);
    memcpy(md, full, 48); /* SHA-384 = first 48 bytes of SHA-512 */
    return 1;
}

static inline unsigned char *CC_SHA384(const void *data, CC_LONG len, unsigned char *md) {
    CC_SHA384_CTX ctx;
    CC_SHA384_Init(&ctx);
    CC_SHA384_Update(&ctx, data, len);
    CC_SHA384_Final(md, &ctx);
    return md;
}

#endif /* COMMONDIGEST_H_COMPAT */
