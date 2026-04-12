//
//  ngtcp2_bridge.h — Android NDK port
//

#ifndef NGTCP2_BRIDGE_H
#define NGTCP2_BRIDGE_H

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include "shared.h"

/* AEAD cipher type identifiers. Kept Apple-named so generated names match
   iOS docs; the Kotlin callbacks interpret these values. */
#define NGTCP2_APPLE_AEAD_AES_128_GCM         0
#define NGTCP2_APPLE_AEAD_AES_256_GCM         1
#define NGTCP2_APPLE_AEAD_CHACHA20_POLY1305   2

/* Cipher type identifiers for header protection. */
#define NGTCP2_ANDROID_HP_AES_128   0
#define NGTCP2_ANDROID_HP_AES_256   1
#define NGTCP2_ANDROID_HP_CHACHA20  2

/* TLS cipher suite IDs for ngtcp2_crypto_ctx_tls */
#define NGTCP2_APPLE_CS_AES_128_GCM_SHA256       0x1301
#define NGTCP2_APPLE_CS_AES_256_GCM_SHA384       0x1302
#define NGTCP2_APPLE_CS_CHACHA20_POLY1305_SHA256 0x1303

/* Message digest types for HKDF. */
#define NGTCP2_ANDROID_MD_SHA256 0
#define NGTCP2_ANDROID_MD_SHA384 1

/* JNI-supplied crypto callback types — mirrors the iOS Swift pattern. */

typedef int (*ngtcp2_android_aead_encrypt_fn)(
    uint8_t *dest, const uint8_t *key, size_t keylen, const uint8_t *nonce,
    size_t noncelen, const uint8_t *plaintext, size_t plaintextlen,
    const uint8_t *aad, size_t aadlen, int aead_type);

typedef int (*ngtcp2_android_aead_decrypt_fn)(
    uint8_t *dest, const uint8_t *key, size_t keylen, const uint8_t *nonce,
    size_t noncelen, const uint8_t *ciphertext, size_t ciphertextlen,
    const uint8_t *aad, size_t aadlen, int aead_type);

/* HMAC-SHA256/384 single-shot. Writes hashlen bytes to dest. */
typedef int (*ngtcp2_android_hmac_fn)(
    uint8_t *dest, const uint8_t *key, size_t keylen,
    const uint8_t *data, size_t datalen, int md_type);

/* AES-ECB single-block encrypt. Writes 16 bytes to dest. */
typedef int (*ngtcp2_android_aes_ecb_fn)(
    uint8_t *dest, const uint8_t *key, size_t keylen,
    const uint8_t *block);

/* ChaCha20 header protection: counter from sample[0..3] LE, nonce from
   sample[4..15], encrypt 5 zero bytes into dest. */
typedef int (*ngtcp2_android_chacha20_hp_fn)(
    uint8_t *dest, const uint8_t *key, size_t keylen,
    const uint8_t *sample);

void ngtcp2_crypto_android_set_callbacks(
    ngtcp2_android_aead_encrypt_fn aead_encrypt,
    ngtcp2_android_aead_decrypt_fn aead_decrypt,
    ngtcp2_android_hmac_fn hmac,
    ngtcp2_android_aes_ecb_fn aes_ecb,
    ngtcp2_android_chacha20_hp_fn chacha20_hp);

/* Versioned ngtcp2 API wrappers — some public API entry points are macros
   that include a version token which is awkward from JNI; these inline
   wrappers take the same shape as the iOS Swift bridge. */

static inline int ngtcp2_swift_conn_client_new(
    ngtcp2_conn **pconn, const ngtcp2_cid *dcid, const ngtcp2_cid *scid,
    const ngtcp2_path *path, uint32_t version,
    const ngtcp2_callbacks *callbacks, const ngtcp2_settings *settings,
    const ngtcp2_transport_params *params, const ngtcp2_mem *mem,
    void *user_data) {
  return ngtcp2_conn_client_new(pconn, dcid, scid, path, version,
                                callbacks, settings, params, mem, user_data);
}

static inline void ngtcp2_swift_settings_default(ngtcp2_settings *settings) {
  ngtcp2_settings_default(settings);
}

static inline void ngtcp2_swift_transport_params_default(
    ngtcp2_transport_params *params) {
  ngtcp2_transport_params_default(params);
}

static inline ngtcp2_ssize ngtcp2_swift_conn_write_pkt(
    ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi,
    uint8_t *dest, size_t destlen, ngtcp2_tstamp ts) {
  return ngtcp2_conn_write_pkt(conn, path, pi, dest, destlen, ts);
}

static inline int ngtcp2_swift_conn_read_pkt(
    ngtcp2_conn *conn, const ngtcp2_path *path, const ngtcp2_pkt_info *pi,
    const uint8_t *pkt, size_t pktlen, ngtcp2_tstamp ts) {
  return ngtcp2_conn_read_pkt(conn, path, pi, pkt, pktlen, ts);
}

static inline ngtcp2_ssize ngtcp2_swift_conn_writev_stream(
    ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi,
    uint8_t *dest, size_t destlen, ngtcp2_ssize *pdatalen,
    uint32_t flags, int64_t stream_id,
    const ngtcp2_vec *datav, size_t datavcnt, ngtcp2_tstamp ts) {
  return ngtcp2_conn_writev_stream(conn, path, pi, dest, destlen,
                                    pdatalen, flags, stream_id,
                                    datav, datavcnt, ts);
}

static inline const ngtcp2_transport_params *
ngtcp2_swift_conn_get_remote_transport_params(ngtcp2_conn *conn) {
  return ngtcp2_conn_get_remote_transport_params(conn);
}

static inline ngtcp2_ssize ngtcp2_swift_conn_write_datagram(
    ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi,
    uint8_t *dest, size_t destlen, int *paccepted,
    uint32_t flags, uint64_t dgram_id,
    const uint8_t *data, size_t datalen, ngtcp2_tstamp ts) {
  return ngtcp2_conn_write_datagram(conn, path, pi, dest, destlen,
                                     paccepted, flags, dgram_id,
                                     data, datalen, ts);
}

#endif /* NGTCP2_BRIDGE_H */
