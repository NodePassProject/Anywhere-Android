//
//  packet_jni_bridge.c
//  Anywhere Android
//
//  JNI bridge for CPacket.h functions.
//

#include <jni.h>
#include <stdlib.h>
#include <string.h>
#include "packet/CPacket.h"

// ---------------------------------------------------------------------------
// nativeXorNonce(byte[] nonce, long seqNum) -> byte[]
// Returns a NEW byte array with the XOR applied. Does NOT mutate the input.
// ---------------------------------------------------------------------------
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeXorNonce(
        JNIEnv *env, jclass clazz, jbyteArray nonce, jlong seqNum) {
    if (nonce == NULL) return NULL;

    jsize len = (*env)->GetArrayLength(env, nonce);
    if (len < 12) return NULL;

    jbyte *nonceBytes = (*env)->GetByteArrayElements(env, nonce, NULL);
    if (nonceBytes == NULL) return NULL;

    // Create a new output array — never mutate the input IV
    jbyteArray result = (*env)->NewByteArray(env, len);
    if (result == NULL) {
        (*env)->ReleaseByteArrayElements(env, nonce, nonceBytes, JNI_ABORT);
        return NULL;
    }

    // Copy input to a local buffer, XOR, then write to result
    uint8_t tmp[12];
    memcpy(tmp, nonceBytes, 12);
    xor_nonce_with_seq(tmp, (uint64_t)seqNum);

    (*env)->ReleaseByteArrayElements(env, nonce, nonceBytes, JNI_ABORT);
    (*env)->SetByteArrayRegion(env, result, 0, 12, (const jbyte *)tmp);

    return result;
}

// ---------------------------------------------------------------------------
// nativeParseTlsHeader(byte[] buffer) -> int[] {success, contentType, recordLen}
// ---------------------------------------------------------------------------
JNIEXPORT jintArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeParseTlsHeader(
        JNIEnv *env, jclass clazz, jbyteArray buffer) {
    if (buffer == NULL) return NULL;

    jsize len = (*env)->GetArrayLength(env, buffer);
    jbyte *buf = (*env)->GetByteArrayElements(env, buffer, NULL);
    if (buf == NULL) return NULL;

    uint8_t contentType = 0;
    uint16_t recordLen = 0;
    int result = parse_tls_header((const uint8_t *)buf, (size_t)len,
                                  &contentType, &recordLen);

    (*env)->ReleaseByteArrayElements(env, buffer, buf, JNI_ABORT);

    if (!result) return NULL;

    jintArray out = (*env)->NewIntArray(env, 3);
    if (out == NULL) return NULL;

    jint values[3];
    values[0] = result;
    values[1] = (jint)contentType;
    values[2] = (jint)recordLen;
    (*env)->SetIntArrayRegion(env, out, 0, 3, values);

    return out;
}

// ---------------------------------------------------------------------------
// nativeTls13UnwrapContent(byte[] data) -> byte[]
// Returns: [contentType, ...payload] or null
// ---------------------------------------------------------------------------
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTls13UnwrapContent(
        JNIEnv *env, jclass clazz, jbyteArray data) {
    if (data == NULL) return NULL;

    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (buf == NULL) return NULL;

    uint8_t contentType = 0;
    ssize_t contentLen = tls13_unwrap_content((const uint8_t *)buf, (size_t)len,
                                              &contentType);

    if (contentLen < 0) {
        (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
        return NULL;
    }

    // Output: 1 byte contentType + contentLen bytes of payload
    jbyteArray out = (*env)->NewByteArray(env, 1 + (jsize)contentLen);
    if (out == NULL) {
        (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
        return NULL;
    }

    jbyte typeByte = (jbyte)contentType;
    (*env)->SetByteArrayRegion(env, out, 0, 1, &typeByte);
    if (contentLen > 0) {
        (*env)->SetByteArrayRegion(env, out, 1, (jsize)contentLen, buf);
    }

    (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
    return out;
}

// ---------------------------------------------------------------------------
// nativeParseDnsQuery(byte[] data) -> String
// ---------------------------------------------------------------------------
JNIEXPORT jstring JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeParseDnsQuery(
        JNIEnv *env, jclass clazz, jbyteArray data) {
    if (data == NULL) return NULL;

    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (buf == NULL) return NULL;

    char domain[256];
    size_t domainLen = sizeof(domain);

    int result = parse_dns_query((const uint8_t *)buf, (size_t)len,
                                 domain, &domainLen);

    (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);

    if (!result) return NULL;

    return (*env)->NewStringUTF(env, domain);
}

// ---------------------------------------------------------------------------
// nativeParseDnsQueryExt(byte[] data) -> Object[] {String domain, Integer qtype}
// ---------------------------------------------------------------------------
JNIEXPORT jobjectArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeParseDnsQueryExt(
        JNIEnv *env, jclass clazz, jbyteArray data) {
    if (data == NULL) return NULL;

    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (buf == NULL) return NULL;

    char domain[256];
    size_t domainLen = sizeof(domain);
    uint16_t qtype = 0;

    int result = parse_dns_query_ext((const uint8_t *)buf, (size_t)len,
                                     domain, &domainLen, &qtype);

    (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);

    if (!result) return NULL;

    jclass objectClass = (*env)->FindClass(env, "java/lang/Object");
    if (objectClass == NULL) return NULL;

    jobjectArray out = (*env)->NewObjectArray(env, 2, objectClass, NULL);
    if (out == NULL) return NULL;

    jstring domainStr = (*env)->NewStringUTF(env, domain);
    if (domainStr == NULL) return NULL;
    (*env)->SetObjectArrayElement(env, out, 0, domainStr);

    jclass integerClass = (*env)->FindClass(env, "java/lang/Integer");
    jmethodID intValueOf = (*env)->GetStaticMethodID(env, integerClass,
                                                      "valueOf",
                                                      "(I)Ljava/lang/Integer;");
    jobject qtypeObj = (*env)->CallStaticObjectMethod(env, integerClass,
                                                      intValueOf, (jint)qtype);
    (*env)->SetObjectArrayElement(env, out, 1, qtypeObj);

    return out;
}

// ---------------------------------------------------------------------------
// nativeGenerateDnsResponse(byte[] queryData, byte[] fakeIp, int qtype) -> byte[]
// ---------------------------------------------------------------------------
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeGenerateDnsResponse(
        JNIEnv *env, jclass clazz, jbyteArray queryData, jbyteArray fakeIp,
        jint qtype) {
    if (queryData == NULL) return NULL;

    jsize queryLen = (*env)->GetArrayLength(env, queryData);
    jbyte *queryBuf = (*env)->GetByteArrayElements(env, queryData, NULL);
    if (queryBuf == NULL) return NULL;

    const uint8_t *fakeIpPtr = NULL;
    jbyte *fakeIpBuf = NULL;
    if (fakeIp != NULL) {
        fakeIpBuf = (*env)->GetByteArrayElements(env, fakeIp, NULL);
        if (fakeIpBuf == NULL) {
            (*env)->ReleaseByteArrayElements(env, queryData, queryBuf, JNI_ABORT);
            return NULL;
        }
        fakeIpPtr = (const uint8_t *)fakeIpBuf;
    }

    // DNS response buffer: max size is generous for typical responses
    uint8_t outBuf[1024];
    int respLen = generate_dns_response((const uint8_t *)queryBuf, (size_t)queryLen,
                                        fakeIpPtr, (uint16_t)qtype,
                                        outBuf, sizeof(outBuf));

    (*env)->ReleaseByteArrayElements(env, queryData, queryBuf, JNI_ABORT);
    if (fakeIpBuf != NULL) {
        (*env)->ReleaseByteArrayElements(env, fakeIp, fakeIpBuf, JNI_ABORT);
    }

    if (respLen <= 0) return NULL;

    jbyteArray out = (*env)->NewByteArray(env, respLen);
    if (out == NULL) return NULL;
    (*env)->SetByteArrayRegion(env, out, 0, respLen, (const jbyte *)outBuf);

    return out;
}

// ---------------------------------------------------------------------------
// nativeParseServerHello(byte[] data) -> byte[34]
// Returns 32 bytes keyShare + 2 bytes cipherSuite (big-endian), or null
// ---------------------------------------------------------------------------
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeParseServerHello(
        JNIEnv *env, jclass clazz, jbyteArray data) {
    if (data == NULL) return NULL;

    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (buf == NULL) return NULL;

    uint8_t keyShare[32];
    uint16_t cipherSuite = 0;

    int result = parse_server_hello((const uint8_t *)buf, (size_t)len,
                                    keyShare, &cipherSuite);

    (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);

    if (!result) return NULL;

    jbyteArray out = (*env)->NewByteArray(env, 34);
    if (out == NULL) return NULL;

    (*env)->SetByteArrayRegion(env, out, 0, 32, (const jbyte *)keyShare);

    // Append cipher suite as 2 bytes big-endian
    jbyte cs[2];
    cs[0] = (jbyte)((cipherSuite >> 8) & 0xFF);
    cs[1] = (jbyte)(cipherSuite & 0xFF);
    (*env)->SetByteArrayRegion(env, out, 32, 2, cs);

    return out;
}

// ---------------------------------------------------------------------------
// nativeFrameUdpPayload(byte[] payload) -> byte[]
// Returns 2-byte big-endian length prefix + payload
// ---------------------------------------------------------------------------
JNIEXPORT jbyteArray JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeFrameUdpPayload(
        JNIEnv *env, jclass clazz, jbyteArray payload) {
    if (payload == NULL) return NULL;

    jsize len = (*env)->GetArrayLength(env, payload);
    if (len > 0xFFFF) return NULL;

    jbyte *payloadBuf = (*env)->GetByteArrayElements(env, payload, NULL);
    if (payloadBuf == NULL) return NULL;

    jsize outLen = 2 + len;
    uint8_t *outBuf = (uint8_t *)malloc(outLen);
    if (outBuf == NULL) {
        (*env)->ReleaseByteArrayElements(env, payload, payloadBuf, JNI_ABORT);
        return NULL;
    }

    frame_udp_payload(outBuf, (const uint8_t *)payloadBuf, (uint16_t)len);

    (*env)->ReleaseByteArrayElements(env, payload, payloadBuf, JNI_ABORT);

    jbyteArray out = (*env)->NewByteArray(env, outLen);
    if (out == NULL) {
        free(outBuf);
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, out, 0, outLen, (const jbyte *)outBuf);

    free(outBuf);
    return out;
}
