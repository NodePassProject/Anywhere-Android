#include <jni.h>
#include <string.h>
#include "blake3/blake3.h"

static void throw_illegal_argument(JNIEnv *env, const char *msg)
{
    jclass cls = (*env)->FindClass(env, "java/lang/IllegalArgumentException");
    if (cls) {
        (*env)->ThrowNew(env, cls, msg);
        (*env)->DeleteLocalRef(env, cls);
    }
}

static void throw_runtime(JNIEnv *env, const char *msg)
{
    jclass cls = (*env)->FindClass(env, "java/lang/RuntimeException");
    if (cls) {
        (*env)->ThrowNew(env, cls, msg);
        (*env)->DeleteLocalRef(env, cls);
    }
}

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

/* BLAKE3 key derivation mode: context string for domain separation.
 * Used by Shadowsocks 2022 for session key and identity subkey derivation. */
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeBlake3DeriveKey(
    JNIEnv *env,
    jclass  clazz,
    jstring context,
    jbyteArray input,
    jint    outLen)
{
    (void)clazz;

    if (!context) {
        throw_illegal_argument(env, "context must not be null");
        return NULL;
    }
    if (!input) {
        throw_illegal_argument(env, "input must not be null");
        return NULL;
    }
    if (outLen <= 0 || outLen > 64) {
        throw_illegal_argument(env, "outLen must be 1..64");
        return NULL;
    }

    const char *ctx_str = (*env)->GetStringUTFChars(env, context, NULL);
    if (!ctx_str) {
        throw_runtime(env, "Failed to access context string");
        return NULL;
    }

    jsize input_len = (*env)->GetArrayLength(env, input);
    jbyte *input_bytes = (*env)->GetByteArrayElements(env, input, NULL);
    if (!input_bytes) {
        (*env)->ReleaseStringUTFChars(env, context, ctx_str);
        throw_runtime(env, "Failed to access input byte array");
        return NULL;
    }

    blake3_hasher hasher;
    uint8_t out[64];

    blake3_hasher_init_derive_key(&hasher, ctx_str);
    blake3_hasher_update(&hasher, (const uint8_t *)input_bytes, (size_t)input_len);
    blake3_hasher_finalize(&hasher, out, (size_t)outLen);

    (*env)->ReleaseStringUTFChars(env, context, ctx_str);
    (*env)->ReleaseByteArrayElements(env, input, input_bytes, JNI_ABORT);

    jbyteArray result = (*env)->NewByteArray(env, outLen);
    if (!result) {
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, result, 0, outLen, (const jbyte *)out);
    return result;
}
