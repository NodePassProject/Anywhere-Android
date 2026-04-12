//
//  ngtcp2_crypto_android.c — Android NDK port of ngtcp2's crypto backend.
//
//  Mirrors the iOS ngtcp2_crypto_apple.c structure, but delegates ALL crypto
//  primitives (AEAD, HMAC, AES-ECB, ChaCha20 header protection) to callbacks
//  registered from Kotlin/Java (JCE) via the JNI bridge. This avoids bundling
//  BoringSSL/OpenSSL while reusing ngtcp2's own packet-protection logic.
//

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <ngtcp2/ngtcp2_crypto.h>

#include "ngtcp2_macro.h"
#include "shared.h"
#include "ngtcp2_bridge.h"

/* --- Cipher type identification --- */

typedef enum {
  NGTCP2_ANDROID_CIPHER_AES_128,
  NGTCP2_ANDROID_CIPHER_AES_256,
  NGTCP2_ANDROID_CIPHER_CHACHA20,
} ngtcp2_android_cipher_type;

typedef struct {
  ngtcp2_android_cipher_type type;
} ngtcp2_android_cipher;

static ngtcp2_android_cipher cipher_aes_128 = {NGTCP2_ANDROID_CIPHER_AES_128};
static ngtcp2_android_cipher cipher_aes_256 = {NGTCP2_ANDROID_CIPHER_AES_256};
static ngtcp2_android_cipher cipher_chacha20 = {NGTCP2_ANDROID_CIPHER_CHACHA20};

typedef enum {
  NGTCP2_ANDROID_AEAD_AES_128_GCM,
  NGTCP2_ANDROID_AEAD_AES_256_GCM,
  NGTCP2_ANDROID_AEAD_CHACHA20_POLY1305,
} ngtcp2_android_aead_type;

typedef struct {
  ngtcp2_android_aead_type type;
} ngtcp2_android_aead;

static ngtcp2_android_aead aead_aes_128_gcm = {NGTCP2_ANDROID_AEAD_AES_128_GCM};
static ngtcp2_android_aead aead_aes_256_gcm = {NGTCP2_ANDROID_AEAD_AES_256_GCM};
static ngtcp2_android_aead aead_chacha20_poly1305 = {
    NGTCP2_ANDROID_AEAD_CHACHA20_POLY1305};

typedef enum {
  NGTCP2_ANDROID_MD_TYPE_SHA256,
  NGTCP2_ANDROID_MD_TYPE_SHA384,
} ngtcp2_android_md_type_e;

typedef struct {
  ngtcp2_android_md_type_e type;
} ngtcp2_android_md;

static ngtcp2_android_md md_sha256 = {NGTCP2_ANDROID_MD_TYPE_SHA256};
static ngtcp2_android_md md_sha384 = {NGTCP2_ANDROID_MD_TYPE_SHA384};

/* --- AEAD context (stores key + cipher type) --- */

typedef struct {
  ngtcp2_android_aead_type type;
  uint8_t key[32]; /* max key size */
  size_t keylen;
} ngtcp2_android_aead_ctx;

/* --- Cipher context (for header protection) --- */

typedef struct {
  ngtcp2_android_cipher_type type;
  uint8_t key[32];
  size_t keylen;
} ngtcp2_android_hp_ctx;

/* --- JNI-provided callback pointers --- */

static ngtcp2_android_aead_encrypt_fn  _aead_encrypt_fn  = NULL;
static ngtcp2_android_aead_decrypt_fn  _aead_decrypt_fn  = NULL;
static ngtcp2_android_hmac_fn          _hmac_fn          = NULL;
static ngtcp2_android_aes_ecb_fn       _aes_ecb_fn       = NULL;
static ngtcp2_android_chacha20_hp_fn   _chacha20_hp_fn   = NULL;

void ngtcp2_crypto_android_set_callbacks(
    ngtcp2_android_aead_encrypt_fn aead_encrypt,
    ngtcp2_android_aead_decrypt_fn aead_decrypt,
    ngtcp2_android_hmac_fn hmac,
    ngtcp2_android_aes_ecb_fn aes_ecb,
    ngtcp2_android_chacha20_hp_fn chacha20_hp) {
  _aead_encrypt_fn = aead_encrypt;
  _aead_decrypt_fn = aead_decrypt;
  _hmac_fn         = hmac;
  _aes_ecb_fn      = aes_ecb;
  _chacha20_hp_fn  = chacha20_hp;
}

/* --- Basic initialization functions --- */

ngtcp2_crypto_aead *ngtcp2_crypto_aead_aes_128_gcm(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(aead, (void *)&aead_aes_128_gcm);
}

ngtcp2_crypto_md *ngtcp2_crypto_md_sha256(ngtcp2_crypto_md *md) {
  md->native_handle = (void *)&md_sha256;
  return md;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
  ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_aes_128_gcm);
  ctx->md.native_handle = (void *)&md_sha256;
  ctx->hp.native_handle = (void *)&cipher_aes_128;
  ctx->max_encryption = 0;
  ctx->max_decryption_failure = 0;
  return ctx;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead,
                                            void *aead_native_handle) {
  aead->native_handle = aead_native_handle;
  aead->max_overhead = 16; /* All QUIC AEAD ciphers have a 16-byte tag */
  return aead;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(aead, (void *)&aead_aes_128_gcm);
}

/* --- Size query functions --- */

size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
  ngtcp2_android_md *m = (ngtcp2_android_md *)md->native_handle;
  switch (m->type) {
  case NGTCP2_ANDROID_MD_TYPE_SHA256: return 32;
  case NGTCP2_ANDROID_MD_TYPE_SHA384: return 48;
  default:                             return 32;
  }
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  ngtcp2_android_aead *a = (ngtcp2_android_aead *)aead->native_handle;
  switch (a->type) {
  case NGTCP2_ANDROID_AEAD_AES_128_GCM:         return 16;
  case NGTCP2_ANDROID_AEAD_AES_256_GCM:         return 32;
  case NGTCP2_ANDROID_AEAD_CHACHA20_POLY1305:   return 32;
  default:                                       return 16;
  }
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  (void)aead;
  return 12; /* All QUIC AEAD ciphers use a 12-byte nonce */
}

/* --- HKDF: delegates HMAC-SHA256/384 to the Kotlin callback --- */

static int android_md_type_id(const ngtcp2_android_md *m) {
  return m->type == NGTCP2_ANDROID_MD_TYPE_SHA384
             ? NGTCP2_ANDROID_MD_SHA384
             : NGTCP2_ANDROID_MD_SHA256;
}

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
  if (!_hmac_fn) return -1;
  ngtcp2_android_md *m = (ngtcp2_android_md *)md->native_handle;
  /* HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM) */
  return _hmac_fn(dest, salt, saltlen, secret, secretlen,
                  android_md_type_id(m));
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md, const uint8_t *secret,
                              size_t secretlen, const uint8_t *info,
                              size_t infolen) {
  if (!_hmac_fn) return -1;
  ngtcp2_android_md *m = (ngtcp2_android_md *)md->native_handle;
  size_t hashlen = ngtcp2_crypto_md_hashlen(md);
  int md_id = android_md_type_id(m);

  uint8_t t[64]; /* max SHA-512 size; SHA-384 is 48 */
  size_t t_len = 0;
  uint8_t counter = 1;
  size_t remaining = destlen;

  /* Scratch buffer: T(i-1) || info || counter */
  uint8_t buf[2048];
  if (hashlen + infolen + 1 > sizeof(buf)) return -1;

  while (remaining > 0) {
    size_t buflen = 0;
    if (t_len > 0) {
      memcpy(buf, t, t_len);
      buflen = t_len;
    }
    memcpy(buf + buflen, info, infolen);
    buflen += infolen;
    buf[buflen++] = counter;

    if (_hmac_fn(t, secret, secretlen, buf, buflen, md_id) != 0) return -1;
    t_len = hashlen;

    size_t to_copy = remaining < hashlen ? remaining : hashlen;
    memcpy(dest, t, to_copy);
    dest += to_copy;
    remaining -= to_copy;
    counter++;
  }
  return 0;
}

int ngtcp2_crypto_hkdf(uint8_t *dest, size_t destlen,
                       const ngtcp2_crypto_md *md, const uint8_t *secret,
                       size_t secretlen, const uint8_t *salt, size_t saltlen,
                       const uint8_t *info, size_t infolen) {
  uint8_t prk[64]; /* max hash output */

  if (ngtcp2_crypto_hkdf_extract(prk, md, secret, secretlen, salt, saltlen) !=
      0) {
    return -1;
  }
  return ngtcp2_crypto_hkdf_expand(dest, destlen, md, prk,
                                   ngtcp2_crypto_md_hashlen(md), info, infolen);
}

/* --- AEAD context management --- */

int ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  ngtcp2_android_aead *a = (ngtcp2_android_aead *)aead->native_handle;
  ngtcp2_android_aead_ctx *ctx;

  (void)noncelen;

  ctx = malloc(sizeof(*ctx));
  if (ctx == NULL) return -1;

  ctx->type = a->type;
  ctx->keylen = ngtcp2_crypto_aead_keylen(aead);
  memcpy(ctx->key, key, ctx->keylen);
  aead_ctx->native_handle = ctx;
  return 0;
}

int ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  return ngtcp2_crypto_aead_ctx_encrypt_init(aead_ctx, aead, key, noncelen);
}

void ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *aead_ctx) {
  if (aead_ctx->native_handle) {
    free(aead_ctx->native_handle);
  }
}

/* --- Cipher (header protection) context management --- */

int ngtcp2_crypto_cipher_ctx_encrypt_init(ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                          const ngtcp2_crypto_cipher *cipher,
                                          const uint8_t *key) {
  ngtcp2_android_cipher *c = (ngtcp2_android_cipher *)cipher->native_handle;
  ngtcp2_android_hp_ctx *ctx;

  ctx = malloc(sizeof(*ctx));
  if (ctx == NULL) return -1;

  ctx->type = c->type;
  switch (c->type) {
  case NGTCP2_ANDROID_CIPHER_AES_128:   ctx->keylen = 16; break;
  case NGTCP2_ANDROID_CIPHER_AES_256:
  case NGTCP2_ANDROID_CIPHER_CHACHA20:  ctx->keylen = 32; break;
  }
  memcpy(ctx->key, key, ctx->keylen);
  cipher_ctx->native_handle = ctx;
  return 0;
}

void ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *cipher_ctx) {
  if (!cipher_ctx->native_handle) return;
  free(cipher_ctx->native_handle);
}

/* --- AEAD encrypt/decrypt via Kotlin callbacks --- */

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  ngtcp2_android_aead_ctx *ctx =
      (ngtcp2_android_aead_ctx *)aead_ctx->native_handle;
  (void)aead;

  if (!_aead_encrypt_fn) return -1;

  return _aead_encrypt_fn(dest, ctx->key, ctx->keylen, nonce, noncelen,
                          plaintext, plaintextlen, aad, aadlen,
                          (int)ctx->type);
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  ngtcp2_android_aead_ctx *ctx =
      (ngtcp2_android_aead_ctx *)aead_ctx->native_handle;
  (void)aead;

  if (!_aead_decrypt_fn) return -1;

  return _aead_decrypt_fn(dest, ctx->key, ctx->keylen, nonce, noncelen,
                          ciphertext, ciphertextlen, aad, aadlen,
                          (int)ctx->type);
}

/* --- Header protection mask --- */

int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const ngtcp2_crypto_cipher_ctx *hp_ctx,
                          const uint8_t *sample) {
  ngtcp2_android_hp_ctx *ctx = (ngtcp2_android_hp_ctx *)hp_ctx->native_handle;
  (void)hp;

  switch (ctx->type) {
  case NGTCP2_ANDROID_CIPHER_AES_128:
  case NGTCP2_ANDROID_CIPHER_AES_256:
    if (!_aes_ecb_fn) return -1;
    return _aes_ecb_fn(dest, ctx->key, ctx->keylen, sample);

  case NGTCP2_ANDROID_CIPHER_CHACHA20:
    if (!_chacha20_hp_fn) return -1;
    return _chacha20_hp_fn(dest, ctx->key, ctx->keylen, sample);

  default:
    return -1;
  }
}

/* --- Secure random (path challenge data, connection IDs, etc.) --- */

static int android_getrandom(uint8_t *data, size_t datalen) {
  int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  size_t remaining = datalen;
  uint8_t *p = data;
  while (remaining > 0) {
    ssize_t n = read(fd, p, remaining);
    if (n < 0) {
      if (errno == EINTR) continue;
      close(fd);
      return -1;
    }
    if (n == 0) { close(fd); return -1; }
    p += n;
    remaining -= (size_t)n;
  }
  close(fd);
  return 0;
}

int ngtcp2_crypto_random(uint8_t *data, size_t datalen) {
  return android_getrandom(data, datalen);
}

int ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data,
                                             void *user_data) {
  (void)conn; (void)user_data;
  if (android_getrandom(data, NGTCP2_PATH_CHALLENGE_DATALEN) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

int ngtcp2_crypto_get_path_challenge_data2_cb(ngtcp2_conn *conn,
                                              ngtcp2_path_challenge_data *data,
                                              void *user_data) {
  (void)conn; (void)user_data;
  if (android_getrandom(data->data, NGTCP2_PATH_CHALLENGE_DATALEN) != 0) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

/* --- TLS integration --- */

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
                                         void *tls_native_handle) {
  /* tls_native_handle encodes the cipher suite ID. */
  if (!tls_native_handle) return NULL;

  uintptr_t cs = (uintptr_t)tls_native_handle;
  switch (cs) {
  case 0x1301: /* TLS_AES_128_GCM_SHA256 */
    ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_aes_128_gcm);
    ctx->md.native_handle = (void *)&md_sha256;
    ctx->hp.native_handle = (void *)&cipher_aes_128;
    ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
    ctx->max_decryption_failure = NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
    break;
  case 0x1302: /* TLS_AES_256_GCM_SHA384 */
    ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_aes_256_gcm);
    ctx->md.native_handle = (void *)&md_sha384;
    ctx->hp.native_handle = (void *)&cipher_aes_256;
    ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
    ctx->max_decryption_failure = NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
    break;
  case 0x1303: /* TLS_CHACHA20_POLY1305_SHA256 */
    ngtcp2_crypto_aead_init(&ctx->aead, (void *)&aead_chacha20_poly1305);
    ctx->md.native_handle = (void *)&md_sha256;
    ctx->hp.native_handle = (void *)&cipher_chacha20;
    ctx->max_encryption = NGTCP2_CRYPTO_MAX_ENCRYPTION_CHACHA20_POLY1305;
    ctx->max_decryption_failure =
        NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_CHACHA20_POLY1305;
    break;
  default:
    return NULL;
  }
  return ctx;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls_early(ngtcp2_crypto_ctx *ctx,
                                               void *tls_native_handle) {
  return ngtcp2_crypto_ctx_tls(ctx, tls_native_handle);
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls) {
  (void)conn; (void)tls;
  return 0;
}

int ngtcp2_crypto_set_local_transport_params(void *tls, const uint8_t *buf,
                                             size_t len) {
  (void)tls; (void)buf; (void)len;
  return 0;
}

int ngtcp2_crypto_read_write_crypto_data(
    ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
    const uint8_t *data, size_t datalen) {
  (void)conn; (void)encryption_level; (void)data; (void)datalen;
  /* TLS is driven from Kotlin */
  return -1;
}
