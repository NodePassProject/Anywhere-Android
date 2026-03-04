//
//  vless_jni_bridge.c
//  Anywhere Android
//
//  JNI bridge for CVLESS.h functions.
//

#include <jni.h>
#include "vless/CVLESS.h"

// ---------------------------------------------------------------------------
// nativeBuildVlessHeader(byte[] uuid, int command, int port,
//                        int addressType, byte[] address) -> byte[]
// ---------------------------------------------------------------------------
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeBuildVlessHeader(
        JNIEnv *env, jclass clazz, jbyteArray uuid, jint command,
        jint port, jint addressType, jbyteArray address) {
    if (uuid == NULL || address == NULL) return NULL;

    jsize uuidLen = (*env)->GetArrayLength(env, uuid);
    if (uuidLen != 16) return NULL;

    jsize addrLen = (*env)->GetArrayLength(env, address);

    jbyte *uuidBuf = (*env)->GetByteArrayElements(env, uuid, NULL);
    if (uuidBuf == NULL) return NULL;

    jbyte *addrBuf = (*env)->GetByteArrayElements(env, address, NULL);
    if (addrBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, uuid, uuidBuf, JNI_ABORT);
        return NULL;
    }

    // Maximum header size: 1 + 16 + 1 + 1 + 2 + 1 + 255 = 277 bytes
    uint8_t headerBuf[512];

    size_t headerLen = build_vless_request_header(
            headerBuf,
            (const uint8_t *)uuidBuf,
            (uint8_t)command,
            (uint16_t)port,
            (uint8_t)addressType,
            (const uint8_t *)addrBuf,
            (size_t)addrLen);

    (*env)->ReleaseByteArrayElements(env, uuid, uuidBuf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, address, addrBuf, JNI_ABORT);

    if (headerLen == 0) return NULL;

    jbyteArray out = (*env)->NewByteArray(env, (jsize)headerLen);
    if (out == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, out, 0, (jsize)headerLen,
                               (const jbyte *)headerBuf);

    return out;
}

// ---------------------------------------------------------------------------
// nativeParseVlessAddress(String address) -> byte[]
// Returns [addressType, ...addressBytes] or null
// ---------------------------------------------------------------------------
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeParseVlessAddress(
        JNIEnv *env, jclass clazz, jstring address) {
    if (address == NULL) return NULL;

    const char *addrCStr = (*env)->GetStringUTFChars(env, address, NULL);
    if (addrCStr == NULL) return NULL;

    size_t strLen = (*env)->GetStringUTFLength(env, address);

    uint8_t outType = 0;
    uint8_t outBytes[255];
    size_t outLen = 0;

    int result = parse_vless_address(addrCStr, strLen,
                                     &outType, outBytes, &outLen);

    (*env)->ReleaseStringUTFChars(env, address, addrCStr);

    if (!result) return NULL;

    // Output: 1 byte type + outLen bytes address data
    jsize totalLen = 1 + (jsize)outLen;
    jbyteArray out = (*env)->NewByteArray(env, totalLen);
    if (out == NULL) return NULL;

    jbyte typeByte = (jbyte)outType;
    (*env)->SetByteArrayRegion(env, out, 0, 1, &typeByte);
    if (outLen > 0) {
        (*env)->SetByteArrayRegion(env, out, 1, (jsize)outLen,
                                   (const jbyte *)outBytes);
    }

    return out;
}
