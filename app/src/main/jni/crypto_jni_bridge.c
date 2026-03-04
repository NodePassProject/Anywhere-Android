/*
 * crypto_jni_bridge.c
 *
 * JNI bridge for BLAKE3 hashing and TLS 1.3 key derivation.
 * Java class: com.argsment.anywhere.vpn.NativeBridge
 */

#include <jni.h>
#include <string.h>
#include "crypto/blake3.h"
#include "crypto/CTLSKeyDerivation.h"

/* --------------------------------------------------------------------------
 * Helper: resolve cipher suite parameters.
 * Returns 0 on success, -1 on unrecognised suite.
 * -------------------------------------------------------------------------- */
static int cipher_suite_params(jint cipher_suite,
                               size_t *out_hash_len,
                               size_t *out_key_len)
{
    switch ((uint16_t)cipher_suite) {
        case TLS_AES_128_GCM_SHA256:
            *out_hash_len = 32;
            *out_key_len  = 16;
            return 0;
        case TLS_AES_256_GCM_SHA384:
            *out_hash_len = 48;
            *out_key_len  = 32;
            return 0;
        default:
            return -1;
    }
}

/* --------------------------------------------------------------------------
 * Helper: throw java.lang.IllegalArgumentException with a message.
 * -------------------------------------------------------------------------- */
static void throw_illegal_argument(JNIEnv *env, const char *msg)
{
    jclass cls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    if (cls) {
        (*env)->ThrowNew(env, cls, msg);
        (*env)->DeleteLocalRef(env, cls);
    }
}

/* --------------------------------------------------------------------------
 * Helper: throw java.lang.RuntimeException with a message.
 * -------------------------------------------------------------------------- */
static void throw_runtime(JNIEnv *env, const char *msg)
{
    jclass cls = (*env)->FindClass(env, "java/lang/RuntimeException");
    if (cls) {
        (*env)->ThrowNew(env, cls, msg);
        (*env)->DeleteLocalRef(env, cls);
    }
}

/* ==========================================================================
 * BLAKE3: nativeBlake3Hash(byte[] input) -> byte[32]
 * ========================================================================== */
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeBlake3Hash(
    JNIEnv *env,
    jclass  clazz,
    jbyteArray input)
{
    (void)clazz;

    if (!input) {
        throw_illegal_argument(env, "input must not be null");
        return NULL;
    }

    jsize input_len = (*env)->GetArrayLength(env, input);
    jbyte *input_bytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (!input_bytes) {
        throw_runtime(env, "Failed to access input byte array");
        return NULL;
    }

    blake3_hasher hasher;
    uint8_t out[BLAKE3_OUT_LEN];

    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, (const uint8_t *)input_bytes, (size_t)input_len);
    blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);

    (*env)->ReleaseByteArrayElements(env, input, input_bytes, JNI_ABORT);

    jbyteArray result = (*env)->NewByteArray(env, BLAKE3_OUT_LEN);
    if (!result) {
        return NULL; /* OutOfMemoryError already pending */
    }
    (*env)->SetByteArrayRegion(env, result, 0, BLAKE3_OUT_LEN, (const jbyte *)out);
    return result;
}

/* ==========================================================================
 * BLAKE3: nativeBlake3KeyedHash(byte[] key, byte[] input) -> byte[32]
 * ========================================================================== */
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeBlake3KeyedHash(
    JNIEnv *env,
    jclass  clazz,
    jbyteArray key,
    jbyteArray input)
{
    (void)clazz;

    if (!key) {
        throw_illegal_argument(env, "key must not be null");
        return NULL;
    }
    if (!input) {
        throw_illegal_argument(env, "input must not be null");
        return NULL;
    }

    jsize key_len = (*env)->GetArrayLength(env, key);
    if (key_len != BLAKE3_KEY_LEN) {
        throw_illegal_argument(env, "key must be exactly 32 bytes");
        return NULL;
    }

    jbyte *key_bytes = (*env)->GetByteArrayElements(env, key, NULL);
    if (!key_bytes) {
        throw_runtime(env, "Failed to access key byte array");
        return NULL;
    }

    jsize input_len = (*env)->GetArrayLength(env, input);
    jbyte *input_bytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (!input_bytes) {
        (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
        throw_runtime(env, "Failed to access input byte array");
        return NULL;
    }

    blake3_hasher hasher;
    uint8_t out[BLAKE3_OUT_LEN];

    blake3_hasher_init_keyed(&hasher, (const uint8_t *)key_bytes);
    blake3_hasher_update(&hasher, (const uint8_t *)input_bytes, (size_t)input_len);
    blake3_hasher_finalize(&hasher, out, BLAKE3_OUT_LEN);

    (*env)->ReleaseByteArrayElements(env, key, key_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, input, input_bytes, JNI_ABORT);

    jbyteArray result = (*env)->NewByteArray(env, BLAKE3_OUT_LEN);
    if (!result) {
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, result, 0, BLAKE3_OUT_LEN, (const jbyte *)out);
    return result;
}

/* ==========================================================================
 * TLS 1.3: nativeTls13DeriveHandshakeKeys(int cipherSuite,
 *              byte[] sharedSecret, byte[] transcript) -> byte[]
 *
 * Returns flat array:
 *   hsSecret(hashLen) + clientKey(keyLen) + clientIV(12) +
 *   serverKey(keyLen) + serverIV(12) + clientTrafficSecret(hashLen)
 * ========================================================================== */
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTls13DeriveHandshakeKeys(
    JNIEnv *env,
    jclass  clazz,
    jint    cipherSuite,
    jbyteArray sharedSecret,
    jbyteArray transcript)
{
    (void)clazz;

    size_t hashLen, keyLen;
    if (cipher_suite_params(cipherSuite, &hashLen, &keyLen) != 0) {
        throw_illegal_argument(env, "Unsupported cipher suite");
        return NULL;
    }
    if (!sharedSecret) {
        throw_illegal_argument(env, "sharedSecret must not be null");
        return NULL;
    }
    if (!transcript) {
        throw_illegal_argument(env, "transcript must not be null");
        return NULL;
    }

    jsize ss_len = (*env)->GetArrayLength(env, sharedSecret);
    jbyte *ss_bytes = (*env)->GetByteArrayElements(env, sharedSecret, NULL);
    if (!ss_bytes) {
        throw_runtime(env, "Failed to access sharedSecret byte array");
        return NULL;
    }

    jsize tr_len = (*env)->GetArrayLength(env, transcript);
    jbyte *tr_bytes = (*env)->GetByteArrayElements(env, transcript, NULL);
    if (!tr_bytes) {
        (*env)->ReleaseByteArrayElements(env, sharedSecret, ss_bytes, JNI_ABORT);
        throw_runtime(env, "Failed to access transcript byte array");
        return NULL;
    }

    /* Allocate output buffers on the stack (max hashLen=48, keyLen=32). */
    uint8_t hs_secret[48];
    uint8_t client_key[32];
    uint8_t client_iv[12];
    uint8_t server_key[32];
    uint8_t server_iv[12];
    uint8_t client_traffic_secret[48];

    int rc = tls13_derive_handshake_keys(
        (uint16_t)cipherSuite,
        (const uint8_t *)ss_bytes, (size_t)ss_len,
        (const uint8_t *)tr_bytes, (size_t)tr_len,
        hs_secret,
        client_key,
        client_iv,
        server_key,
        server_iv,
        client_traffic_secret);

    (*env)->ReleaseByteArrayElements(env, sharedSecret, ss_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, transcript, tr_bytes, JNI_ABORT);

    if (rc != 0) {
        throw_runtime(env, "tls13_derive_handshake_keys failed");
        return NULL;
    }

    /* Total output: hashLen + keyLen + 12 + keyLen + 12 + hashLen */
    jsize total = (jsize)(hashLen + keyLen + 12 + keyLen + 12 + hashLen);
    jbyteArray result = (*env)->NewByteArray(env, total);
    if (!result) {
        return NULL;
    }

    jsize offset = 0;
    (*env)->SetByteArrayRegion(env, result, offset, (jsize)hashLen, (const jbyte *)hs_secret);
    offset += (jsize)hashLen;

    (*env)->SetByteArrayRegion(env, result, offset, (jsize)keyLen, (const jbyte *)client_key);
    offset += (jsize)keyLen;

    (*env)->SetByteArrayRegion(env, result, offset, 12, (const jbyte *)client_iv);
    offset += 12;

    (*env)->SetByteArrayRegion(env, result, offset, (jsize)keyLen, (const jbyte *)server_key);
    offset += (jsize)keyLen;

    (*env)->SetByteArrayRegion(env, result, offset, 12, (const jbyte *)server_iv);
    offset += 12;

    (*env)->SetByteArrayRegion(env, result, offset, (jsize)hashLen, (const jbyte *)client_traffic_secret);

    return result;
}

/* ==========================================================================
 * TLS 1.3: nativeTls13DeriveApplicationKeys(int cipherSuite,
 *              byte[] hsSecret, byte[] transcript) -> byte[]
 *
 * Returns flat array:
 *   clientKey(keyLen) + clientIV(12) + serverKey(keyLen) + serverIV(12)
 * ========================================================================== */
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTls13DeriveApplicationKeys(
    JNIEnv *env,
    jclass  clazz,
    jint    cipherSuite,
    jbyteArray hsSecret,
    jbyteArray transcript)
{
    (void)clazz;

    size_t hashLen, keyLen;
    if (cipher_suite_params(cipherSuite, &hashLen, &keyLen) != 0) {
        throw_illegal_argument(env, "Unsupported cipher suite");
        return NULL;
    }
    if (!hsSecret) {
        throw_illegal_argument(env, "hsSecret must not be null");
        return NULL;
    }
    if (!transcript) {
        throw_illegal_argument(env, "transcript must not be null");
        return NULL;
    }

    jsize hs_len = (*env)->GetArrayLength(env, hsSecret);
    jbyte *hs_bytes = (*env)->GetByteArrayElements(env, hsSecret, NULL);
    if (!hs_bytes) {
        throw_runtime(env, "Failed to access hsSecret byte array");
        return NULL;
    }

    jsize tr_len = (*env)->GetArrayLength(env, transcript);
    jbyte *tr_bytes = (*env)->GetByteArrayElements(env, transcript, NULL);
    if (!tr_bytes) {
        (*env)->ReleaseByteArrayElements(env, hsSecret, hs_bytes, JNI_ABORT);
        throw_runtime(env, "Failed to access transcript byte array");
        return NULL;
    }

    uint8_t client_key[32];
    uint8_t client_iv[12];
    uint8_t server_key[32];
    uint8_t server_iv[12];

    int rc = tls13_derive_application_keys(
        (uint16_t)cipherSuite,
        (const uint8_t *)hs_bytes, (size_t)hs_len,
        (const uint8_t *)tr_bytes, (size_t)tr_len,
        client_key,
        client_iv,
        server_key,
        server_iv);

    (*env)->ReleaseByteArrayElements(env, hsSecret, hs_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, transcript, tr_bytes, JNI_ABORT);

    if (rc != 0) {
        throw_runtime(env, "tls13_derive_application_keys failed");
        return NULL;
    }

    /* Total output: keyLen + 12 + keyLen + 12 */
    jsize total = (jsize)(keyLen + 12 + keyLen + 12);
    jbyteArray result = (*env)->NewByteArray(env, total);
    if (!result) {
        return NULL;
    }

    jsize offset = 0;
    (*env)->SetByteArrayRegion(env, result, offset, (jsize)keyLen, (const jbyte *)client_key);
    offset += (jsize)keyLen;

    (*env)->SetByteArrayRegion(env, result, offset, 12, (const jbyte *)client_iv);
    offset += 12;

    (*env)->SetByteArrayRegion(env, result, offset, (jsize)keyLen, (const jbyte *)server_key);
    offset += (jsize)keyLen;

    (*env)->SetByteArrayRegion(env, result, offset, 12, (const jbyte *)server_iv);

    return result;
}

/* ==========================================================================
 * TLS 1.3: nativeTls13ComputeFinished(int cipherSuite,
 *              byte[] clientTrafficSecret, byte[] transcript) -> byte[]
 *
 * Returns: verifyData (hashLen bytes: 32 or 48)
 * ========================================================================== */
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTls13ComputeFinished(
    JNIEnv *env,
    jclass  clazz,
    jint    cipherSuite,
    jbyteArray clientTrafficSecret,
    jbyteArray transcript)
{
    (void)clazz;

    size_t hashLen, keyLen;
    if (cipher_suite_params(cipherSuite, &hashLen, &keyLen) != 0) {
        throw_illegal_argument(env, "Unsupported cipher suite");
        return NULL;
    }
    if (!clientTrafficSecret) {
        throw_illegal_argument(env, "clientTrafficSecret must not be null");
        return NULL;
    }
    if (!transcript) {
        throw_illegal_argument(env, "transcript must not be null");
        return NULL;
    }

    jsize secret_len = (*env)->GetArrayLength(env, clientTrafficSecret);
    jbyte *secret_bytes = (*env)->GetByteArrayElements(env, clientTrafficSecret, NULL);
    if (!secret_bytes) {
        throw_runtime(env, "Failed to access clientTrafficSecret byte array");
        return NULL;
    }

    jsize tr_len = (*env)->GetArrayLength(env, transcript);
    jbyte *tr_bytes = (*env)->GetByteArrayElements(env, transcript, NULL);
    if (!tr_bytes) {
        (*env)->ReleaseByteArrayElements(env, clientTrafficSecret, secret_bytes, JNI_ABORT);
        throw_runtime(env, "Failed to access transcript byte array");
        return NULL;
    }

    uint8_t verify_data[48];

    int rc = tls13_compute_finished(
        (uint16_t)cipherSuite,
        (const uint8_t *)secret_bytes, (size_t)secret_len,
        (const uint8_t *)tr_bytes, (size_t)tr_len,
        verify_data);

    (*env)->ReleaseByteArrayElements(env, clientTrafficSecret, secret_bytes, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, transcript, tr_bytes, JNI_ABORT);

    if (rc != 0) {
        throw_runtime(env, "tls13_compute_finished failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)hashLen);
    if (!result) {
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)hashLen, (const jbyte *)verify_data);
    return result;
}

/* ==========================================================================
 * TLS 1.3: nativeTls13TranscriptHash(int cipherSuite,
 *              byte[] messages) -> byte[]
 *
 * Returns: hash (hashLen bytes: 32 or 48)
 * ========================================================================== */
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTls13TranscriptHash(
    JNIEnv *env,
    jclass  clazz,
    jint    cipherSuite,
    jbyteArray messages)
{
    (void)clazz;

    size_t hashLen, keyLen;
    if (cipher_suite_params(cipherSuite, &hashLen, &keyLen) != 0) {
        throw_illegal_argument(env, "Unsupported cipher suite");
        return NULL;
    }
    if (!messages) {
        throw_illegal_argument(env, "messages must not be null");
        return NULL;
    }

    jsize msg_len = (*env)->GetArrayLength(env, messages);
    jbyte *msg_bytes = (*env)->GetByteArrayElements(env, messages, NULL);
    if (!msg_bytes) {
        throw_runtime(env, "Failed to access messages byte array");
        return NULL;
    }

    uint8_t hash_out[48];

    int rc = tls13_transcript_hash(
        (uint16_t)cipherSuite,
        (const uint8_t *)msg_bytes, (size_t)msg_len,
        hash_out);

    (*env)->ReleaseByteArrayElements(env, messages, msg_bytes, JNI_ABORT);

    if (rc != 0) {
        throw_runtime(env, "tls13_transcript_hash failed");
        return NULL;
    }

    jbyteArray result = (*env)->NewByteArray(env, (jsize)hashLen);
    if (!result) {
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, result, 0, (jsize)hashLen, (const jbyte *)hash_out);
    return result;
}
