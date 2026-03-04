/*
 * CommonHMAC.h — CommonCrypto compatibility shim for Android NDK.
 *
 * Provides HMAC-SHA256 and HMAC-SHA384 so that CTLSKeyDerivation.c
 * can compile unchanged.
 */

#ifndef COMMONHMAC_H_COMPAT
#define COMMONHMAC_H_COMPAT

#include "CommonDigest.h"

typedef enum {
    kCCHmacAlgSHA256 = 2,
    kCCHmacAlgSHA384 = 5
} CCHmacAlgorithm;

/* HMAC context — large enough for either SHA-256 or SHA-384 */
typedef struct {
    CCHmacAlgorithm alg;
    int             hash_len;
    int             block_size;
    uint8_t         i_key_pad[128];
    uint8_t         o_key_pad[128];
    /* Union of SHA-256 and SHA-512 contexts */
    union {
        CC_SHA256_CTX sha256;
        CC_SHA512_CTX sha512;
    } inner;
} CCHmacContext;

static inline int _hmac_params(CCHmacAlgorithm alg, int *hash_len, int *block_size) {
    if (alg == kCCHmacAlgSHA384) {
        *hash_len = 48; *block_size = 128; return 1;
    } else {
        *hash_len = 32; *block_size = 64; return 1;
    }
}

static inline void CCHmacInit(CCHmacContext *ctx, CCHmacAlgorithm alg,
                               const void *key, size_t keyLength) {
    int hash_len, block_size;
    _hmac_params(alg, &hash_len, &block_size);
    ctx->alg = alg;
    ctx->hash_len = hash_len;
    ctx->block_size = block_size;

    uint8_t key_block[128];
    memset(key_block, 0, sizeof(key_block));

    if ((int)keyLength > block_size) {
        /* Hash the key if it's longer than block size */
        if (alg == kCCHmacAlgSHA384) {
            CC_SHA384(key, (CC_LONG)keyLength, key_block);
        } else {
            CC_SHA256(key, (CC_LONG)keyLength, key_block);
        }
    } else {
        memcpy(key_block, key, keyLength);
    }

    for (int i = 0; i < block_size; i++) {
        ctx->i_key_pad[i] = key_block[i] ^ 0x36;
        ctx->o_key_pad[i] = key_block[i] ^ 0x5c;
    }

    /* Init inner hash with i_key_pad */
    if (alg == kCCHmacAlgSHA384) {
        CC_SHA384_Init(&ctx->inner.sha512);
        CC_SHA384_Update(&ctx->inner.sha512, ctx->i_key_pad, (CC_LONG)block_size);
    } else {
        CC_SHA256_Init(&ctx->inner.sha256);
        CC_SHA256_Update(&ctx->inner.sha256, ctx->i_key_pad, (CC_LONG)block_size);
    }
}

static inline void CCHmacUpdate(CCHmacContext *ctx, const void *data, size_t dataLength) {
    if (ctx->alg == kCCHmacAlgSHA384) {
        CC_SHA384_Update(&ctx->inner.sha512, data, (CC_LONG)dataLength);
    } else {
        CC_SHA256_Update(&ctx->inner.sha256, data, (CC_LONG)dataLength);
    }
}

static inline void CCHmacFinal(CCHmacContext *ctx, void *macOut) {
    uint8_t inner_hash[64]; /* max SHA-512 output */

    if (ctx->alg == kCCHmacAlgSHA384) {
        CC_SHA384_Final(inner_hash, &ctx->inner.sha512);
        /* Outer hash: H(o_key_pad || inner_hash) */
        CC_SHA512_CTX outer;
        CC_SHA384_Init(&outer);
        CC_SHA384_Update(&outer, ctx->o_key_pad, (CC_LONG)ctx->block_size);
        CC_SHA384_Update(&outer, inner_hash, (CC_LONG)ctx->hash_len);
        CC_SHA384_Final((uint8_t *)macOut, &outer);
    } else {
        CC_SHA256_Final(inner_hash, &ctx->inner.sha256);
        CC_SHA256_CTX outer;
        CC_SHA256_Init(&outer);
        CC_SHA256_Update(&outer, ctx->o_key_pad, (CC_LONG)ctx->block_size);
        CC_SHA256_Update(&outer, inner_hash, (CC_LONG)ctx->hash_len);
        CC_SHA256_Final((uint8_t *)macOut, &outer);
    }
}

/* One-shot HMAC */
static inline void CCHmac(CCHmacAlgorithm alg, const void *key, size_t keyLength,
                           const void *data, size_t dataLength, void *macOut) {
    CCHmacContext ctx;
    CCHmacInit(&ctx, alg, key, keyLength);
    CCHmacUpdate(&ctx, data, dataLength);
    CCHmacFinal(&ctx, macOut);
}

#endif /* COMMONHMAC_H_COMPAT */
