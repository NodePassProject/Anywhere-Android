//
//  geoip_jni_bridge.c
//  Anywhere Android
//
//  JNI bridge for CGeoIP.h functions.
//

#include <jni.h>
#include "geoip/CGeoIP.h"

// ---------------------------------------------------------------------------
// nativeGeoipLookup(byte[] database, String ipStr) -> String
// Returns 2-char country code or empty string if not found.
// ---------------------------------------------------------------------------
JNIEXPORT jstring JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeGeoipLookup(
        JNIEnv *env, jclass clazz, jbyteArray database, jstring ipStr) {
    if (database == NULL || ipStr == NULL) {
        return (*env)->NewStringUTF(env, "");
    }

    jsize dbLen = (*env)->GetArrayLength(env, database);
    jbyte *dbBuf = (*env)->GetByteArrayElements(env, database, NULL);
    if (dbBuf == NULL) {
        return (*env)->NewStringUTF(env, "");
    }

    const char *ipCStr = (*env)->GetStringUTFChars(env, ipStr, NULL);
    if (ipCStr == NULL) {
        (*env)->ReleaseByteArrayElements(env, database, dbBuf, JNI_ABORT);
        return (*env)->NewStringUTF(env, "");
    }

    uint16_t code = geoip_lookup((const uint8_t *)dbBuf, (size_t)dbLen, ipCStr);

    (*env)->ReleaseStringUTFChars(env, ipStr, ipCStr);
    (*env)->ReleaseByteArrayElements(env, database, dbBuf, JNI_ABORT);

    if (code == 0) {
        return (*env)->NewStringUTF(env, "");
    }

    // Packed UInt16 country code: high byte is first char, low byte is second char
    char country[3];
    country[0] = (char)((code >> 8) & 0xFF);
    country[1] = (char)(code & 0xFF);
    country[2] = '\0';

    return (*env)->NewStringUTF(env, country);
}
