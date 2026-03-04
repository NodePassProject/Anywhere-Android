/*
 * lwip_jni_bridge.c
 *
 * JNI bridge for lwIP — replaces the iOS Swift callback mechanism with
 * JNI callbacks to Kotlin.  The Kotlin class is
 *     com.argsment.anywhere.vpn.NativeBridge
 *
 * Every native method in NativeBridge.kt maps to a
 *     Java_com_argsment_anywhere_vpn_NativeBridge_nativeXxx
 * function here.
 *
 * Callbacks from C into Kotlin go through cached jmethodID handles that
 * are resolved once in nativeInit and reused for the lifetime of the
 * bridge.  Because lwIP callbacks may fire on a worker thread we always
 * obtain a valid JNIEnv* via AttachCurrentThread before calling into the
 * JVM.
 */

#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <stdint.h>

#include "lwip/lwip_bridge.h"

/* ------------------------------------------------------------------ */
/*  Logging                                                            */
/* ------------------------------------------------------------------ */

#define LOG_TAG "LwipJniBridge"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/*  Cached JNI state                                                   */
/* ------------------------------------------------------------------ */

static JavaVM  *g_jvm           = NULL;   /* set in JNI_OnLoad               */
static jclass    g_bridge_class = NULL;   /* global ref to NativeBridge class */

/* Pre-allocated output buffer — reused across calls to avoid per-packet
   allocation.  Safe because all lwIP callbacks run on a single thread and
   the Java onOutput writes synchronously before returning. */
static jbyteArray g_output_buf      = NULL;   /* global ref                */
static int        g_output_buf_cap  = 0;      /* current capacity in bytes */

/* Cached method IDs for callbacks from C -> Kotlin */
static jmethodID g_onOutput_mid      = NULL;
static jmethodID g_onTcpAccept_mid   = NULL;
static jmethodID g_onTcpRecv_mid     = NULL;
static jmethodID g_onTcpSent_mid     = NULL;
static jmethodID g_onTcpErr_mid      = NULL;
static jmethodID g_onUdpRecv_mid     = NULL;

/* ------------------------------------------------------------------ */
/*  Helper: get a JNIEnv* for the calling thread                       */
/* ------------------------------------------------------------------ */

static JNIEnv *get_env(int *did_attach) {
    JNIEnv *env = NULL;
    *did_attach = 0;

    if (g_jvm == NULL) {
        LOGE("get_env: JavaVM is NULL");
        return NULL;
    }

    jint status = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (status == JNI_OK) {
        return env;
    }

    if (status == JNI_EDETACHED) {
        status = (*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL);
        if (status == JNI_OK) {
            *did_attach = 1;
            return env;
        }
        LOGE("get_env: AttachCurrentThread failed (%d)", status);
        return NULL;
    }

    LOGE("get_env: GetEnv failed (%d)", status);
    return NULL;
}

static void release_env(int did_attach) {
    if (did_attach && g_jvm != NULL) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }
}

/* ------------------------------------------------------------------ */
/*  JNI_OnLoad — cache JavaVM*                                         */
/* ------------------------------------------------------------------ */

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void)reserved;
    g_jvm = vm;
    LOGI("JNI_OnLoad: JavaVM cached");
    return JNI_VERSION_1_6;
}

/* ------------------------------------------------------------------ */
/*  C callback implementations (registered with lwip_bridge_set_*_fn)  */
/* ------------------------------------------------------------------ */

/*
 * lwip_output_fn: lwIP wants to send a packet out through the TUN.
 * Uses a pre-allocated byte array (g_output_buf) to avoid per-packet
 * allocation.  The buffer is grown if a packet exceeds its capacity.
 *
 * Signature of Kotlin method:
 *     fun onOutput(packet: ByteArray, length: Int, isIpv6: Boolean)
 */
static void jni_output_cb(const void *data, int len, int is_ipv6) {
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (env == NULL || g_bridge_class == NULL || g_onOutput_mid == NULL) {
        LOGE("jni_output_cb: JNI state not ready");
        release_env(did_attach);
        return;
    }

    /* Grow the reusable buffer if needed (rare — MTU is typically 1400). */
    if (g_output_buf == NULL || len > g_output_buf_cap) {
        if (g_output_buf != NULL) {
            (*env)->DeleteGlobalRef(env, g_output_buf);
        }
        int cap = len > 2048 ? len : 2048;
        jbyteArray local = (*env)->NewByteArray(env, cap);
        if (local == NULL) {
            LOGE("jni_output_cb: NewByteArray failed (cap=%d)", cap);
            g_output_buf = NULL;
            g_output_buf_cap = 0;
            release_env(did_attach);
            return;
        }
        g_output_buf = (jbyteArray)(*env)->NewGlobalRef(env, local);
        (*env)->DeleteLocalRef(env, local);
        g_output_buf_cap = cap;
    }

    (*env)->SetByteArrayRegion(env, g_output_buf, 0, len, (const jbyte *)data);

    (*env)->CallStaticVoidMethod(env, g_bridge_class, g_onOutput_mid,
                                 g_output_buf, (jint)len,
                                 (jboolean)(is_ipv6 != 0));

    release_env(did_attach);
}

/*
 * lwip_tcp_accept_fn: new TCP connection accepted.
 * Signature of Kotlin method:
 *     fun onTcpAccept(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray,
 *                     dstPort: Int, isIpv6: Boolean, pcb: Long): Long
 * Returns a connection ID (or 0 to abort).
 */
static void *jni_tcp_accept_cb(const void *src_ip, uint16_t src_port,
                                const void *dst_ip, uint16_t dst_port,
                                int is_ipv6, void *pcb) {
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (env == NULL || g_bridge_class == NULL || g_onTcpAccept_mid == NULL) {
        LOGE("jni_tcp_accept_cb: JNI state not ready");
        release_env(did_attach);
        return NULL;
    }

    int addr_len = is_ipv6 ? 16 : 4;

    jbyteArray j_src_ip = (*env)->NewByteArray(env, addr_len);
    jbyteArray j_dst_ip = (*env)->NewByteArray(env, addr_len);
    if (j_src_ip == NULL || j_dst_ip == NULL) {
        LOGE("jni_tcp_accept_cb: NewByteArray failed");
        if (j_src_ip) (*env)->DeleteLocalRef(env, j_src_ip);
        if (j_dst_ip) (*env)->DeleteLocalRef(env, j_dst_ip);
        release_env(did_attach);
        return NULL;
    }
    (*env)->SetByteArrayRegion(env, j_src_ip, 0, addr_len, (const jbyte *)src_ip);
    (*env)->SetByteArrayRegion(env, j_dst_ip, 0, addr_len, (const jbyte *)dst_ip);

    jlong conn_id = (*env)->CallStaticLongMethod(env, g_bridge_class, g_onTcpAccept_mid,
                                                  j_src_ip, (jint)src_port,
                                                  j_dst_ip, (jint)dst_port,
                                                  (jboolean)(is_ipv6 != 0),
                                                  (jlong)(intptr_t)pcb);

    (*env)->DeleteLocalRef(env, j_src_ip);
    (*env)->DeleteLocalRef(env, j_dst_ip);
    release_env(did_attach);

    return (void *)(intptr_t)conn_id;
}

/*
 * lwip_tcp_recv_fn: data received on a TCP connection.
 * Signature of Kotlin method:
 *     fun onTcpRecv(connId: Long, data: ByteArray?)
 * data is null when FIN received (remote closed).
 */
static void jni_tcp_recv_cb(void *conn, const void *data, int len) {
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (env == NULL || g_bridge_class == NULL || g_onTcpRecv_mid == NULL) {
        LOGE("jni_tcp_recv_cb: JNI state not ready");
        release_env(did_attach);
        return;
    }

    jlong conn_id = (jlong)(intptr_t)conn;
    jbyteArray j_data = NULL;

    if (data != NULL && len > 0) {
        j_data = (*env)->NewByteArray(env, len);
        if (j_data == NULL) {
            LOGE("jni_tcp_recv_cb: NewByteArray failed (len=%d)", len);
            release_env(did_attach);
            return;
        }
        (*env)->SetByteArrayRegion(env, j_data, 0, len, (const jbyte *)data);
    }
    /* data==NULL or len<=0 -> pass null to Kotlin to indicate FIN */

    (*env)->CallStaticVoidMethod(env, g_bridge_class, g_onTcpRecv_mid, conn_id, j_data);

    if (j_data != NULL) {
        (*env)->DeleteLocalRef(env, j_data);
    }
    release_env(did_attach);
}

/*
 * lwip_tcp_sent_fn: ACK received, send buffer space freed.
 * Signature of Kotlin method:
 *     fun onTcpSent(connId: Long, length: Int)
 */
static void jni_tcp_sent_cb(void *conn, uint16_t len) {
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (env == NULL || g_bridge_class == NULL || g_onTcpSent_mid == NULL) {
        LOGE("jni_tcp_sent_cb: JNI state not ready");
        release_env(did_attach);
        return;
    }

    (*env)->CallStaticVoidMethod(env, g_bridge_class, g_onTcpSent_mid,
                                  (jlong)(intptr_t)conn, (jint)len);

    release_env(did_attach);
}

/*
 * lwip_tcp_err_fn: TCP error or connection aborted.
 * Signature of Kotlin method:
 *     fun onTcpErr(connId: Long, err: Int)
 */
static void jni_tcp_err_cb(void *conn, int err) {
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (env == NULL || g_bridge_class == NULL || g_onTcpErr_mid == NULL) {
        LOGE("jni_tcp_err_cb: JNI state not ready");
        release_env(did_attach);
        return;
    }

    (*env)->CallStaticVoidMethod(env, g_bridge_class, g_onTcpErr_mid,
                                  (jlong)(intptr_t)conn, (jint)err);

    release_env(did_attach);
}

/*
 * lwip_udp_recv_fn: UDP datagram received.
 * Signature of Kotlin method:
 *     fun onUdpRecv(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray,
 *                   dstPort: Int, isIpv6: Boolean, data: ByteArray)
 */
static void jni_udp_recv_cb(const void *src_ip, uint16_t src_port,
                              const void *dst_ip, uint16_t dst_port,
                              int is_ipv6, const void *data, int len) {
    int did_attach = 0;
    JNIEnv *env = get_env(&did_attach);
    if (env == NULL || g_bridge_class == NULL || g_onUdpRecv_mid == NULL) {
        LOGE("jni_udp_recv_cb: JNI state not ready");
        release_env(did_attach);
        return;
    }

    int addr_len = is_ipv6 ? 16 : 4;

    jbyteArray j_src_ip = (*env)->NewByteArray(env, addr_len);
    jbyteArray j_dst_ip = (*env)->NewByteArray(env, addr_len);
    jbyteArray j_data   = (*env)->NewByteArray(env, len);
    if (j_src_ip == NULL || j_dst_ip == NULL || j_data == NULL) {
        LOGE("jni_udp_recv_cb: NewByteArray failed");
        if (j_src_ip) (*env)->DeleteLocalRef(env, j_src_ip);
        if (j_dst_ip) (*env)->DeleteLocalRef(env, j_dst_ip);
        if (j_data)   (*env)->DeleteLocalRef(env, j_data);
        release_env(did_attach);
        return;
    }
    (*env)->SetByteArrayRegion(env, j_src_ip, 0, addr_len, (const jbyte *)src_ip);
    (*env)->SetByteArrayRegion(env, j_dst_ip, 0, addr_len, (const jbyte *)dst_ip);
    (*env)->SetByteArrayRegion(env, j_data,   0, len,      (const jbyte *)data);

    (*env)->CallStaticVoidMethod(env, g_bridge_class, g_onUdpRecv_mid,
                                  j_src_ip, (jint)src_port,
                                  j_dst_ip, (jint)dst_port,
                                  (jboolean)(is_ipv6 != 0),
                                  j_data);

    (*env)->DeleteLocalRef(env, j_src_ip);
    (*env)->DeleteLocalRef(env, j_dst_ip);
    (*env)->DeleteLocalRef(env, j_data);
    release_env(did_attach);
}

/* ------------------------------------------------------------------ */
/*  JNI native methods exposed to Kotlin                               */
/* ------------------------------------------------------------------ */

/*
 * nativeInit() — initialise lwIP, register all C-to-Java callbacks.
 */
JNIEXPORT void JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeInit(JNIEnv *env, jclass clazz) {
    LOGI("nativeInit: starting");

    /* For @JvmStatic methods in a Kotlin object, the second JNI parameter
       is jclass (the NativeBridge class itself), not a jobject instance.
       Store a global reference to the class for use in static callbacks. */
    if (g_bridge_class != NULL) {
        (*env)->DeleteGlobalRef(env, g_bridge_class);
    }
    g_bridge_class = (*env)->NewGlobalRef(env, clazz);
    if (g_bridge_class == NULL) {
        LOGE("nativeInit: NewGlobalRef failed");
        return;
    }

    /* Cache all static callback method IDs. */
    g_onOutput_mid = (*env)->GetStaticMethodID(env, clazz,
        "onOutput", "([BIZ)V");
    if (g_onOutput_mid == NULL) {
        LOGE("nativeInit: could not find onOutput");
        return;
    }

    g_onTcpAccept_mid = (*env)->GetStaticMethodID(env, clazz,
        "onTcpAccept", "([BI[BIZJ)J");
    if (g_onTcpAccept_mid == NULL) {
        LOGE("nativeInit: could not find onTcpAccept");
        return;
    }

    g_onTcpRecv_mid = (*env)->GetStaticMethodID(env, clazz,
        "onTcpRecv", "(J[B)V");
    if (g_onTcpRecv_mid == NULL) {
        LOGE("nativeInit: could not find onTcpRecv");
        return;
    }

    g_onTcpSent_mid = (*env)->GetStaticMethodID(env, clazz,
        "onTcpSent", "(JI)V");
    if (g_onTcpSent_mid == NULL) {
        LOGE("nativeInit: could not find onTcpSent");
        return;
    }

    g_onTcpErr_mid = (*env)->GetStaticMethodID(env, clazz,
        "onTcpErr", "(JI)V");
    if (g_onTcpErr_mid == NULL) {
        LOGE("nativeInit: could not find onTcpErr");
        return;
    }

    g_onUdpRecv_mid = (*env)->GetStaticMethodID(env, clazz,
        "onUdpRecv", "([BI[BIZ[B)V");
    if (g_onUdpRecv_mid == NULL) {
        LOGE("nativeInit: could not find onUdpRecv");
        return;
    }

    /* Register our C callback functions with lwip_bridge. */
    lwip_bridge_set_output_fn(jni_output_cb);
    lwip_bridge_set_tcp_accept_fn(jni_tcp_accept_cb);
    lwip_bridge_set_tcp_recv_fn(jni_tcp_recv_cb);
    lwip_bridge_set_tcp_sent_fn(jni_tcp_sent_cb);
    lwip_bridge_set_tcp_err_fn(jni_tcp_err_cb);
    lwip_bridge_set_udp_recv_fn(jni_udp_recv_cb);

    /* Initialise lwIP itself. */
    lwip_bridge_init();

    LOGI("nativeInit: done");
}

/*
 * nativeInput(packet: ByteArray, length: Int) — feed a raw IP packet
 * (read from TUN) into lwIP.
 */
JNIEXPORT void JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeInput(JNIEnv *env, jobject thiz,
                                                        jbyteArray packet, jint length) {
    (void)thiz;

    if (packet == NULL || length <= 0) {
        LOGW("nativeInput: invalid arguments");
        return;
    }

    jbyte *buf = (*env)->GetByteArrayElements(env, packet, NULL);
    if (buf == NULL) {
        LOGE("nativeInput: GetByteArrayElements failed");
        return;
    }

    lwip_bridge_input((const void *)buf, (int)length);

    (*env)->ReleaseByteArrayElements(env, packet, buf, JNI_ABORT);
}

/*
 * nativeTimerPoll() — drive lwIP internal timers.
 */
JNIEXPORT void JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTimerPoll(JNIEnv *env, jobject thiz) {
    (void)env;
    (void)thiz;
    lwip_bridge_check_timeouts();
}

/*
 * nativeShutdown() — tear down lwIP and release JNI resources.
 */
JNIEXPORT void JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeShutdown(JNIEnv *env, jobject thiz) {
    (void)thiz;
    LOGI("nativeShutdown: starting");

    lwip_bridge_shutdown();

    /* Clear callback registrations. */
    lwip_bridge_set_output_fn(NULL);
    lwip_bridge_set_tcp_accept_fn(NULL);
    lwip_bridge_set_tcp_recv_fn(NULL);
    lwip_bridge_set_tcp_sent_fn(NULL);
    lwip_bridge_set_tcp_err_fn(NULL);
    lwip_bridge_set_udp_recv_fn(NULL);

    /* Release the pre-allocated output buffer. */
    if (g_output_buf != NULL) {
        (*env)->DeleteGlobalRef(env, g_output_buf);
        g_output_buf = NULL;
        g_output_buf_cap = 0;
    }

    /* Release the global reference to NativeBridge class. */
    if (g_bridge_class != NULL) {
        (*env)->DeleteGlobalRef(env, g_bridge_class);
        g_bridge_class = NULL;
    }

    /* Invalidate cached method IDs. */
    g_onOutput_mid    = NULL;
    g_onTcpAccept_mid = NULL;
    g_onTcpRecv_mid   = NULL;
    g_onTcpSent_mid   = NULL;
    g_onTcpErr_mid    = NULL;
    g_onUdpRecv_mid   = NULL;

    LOGI("nativeShutdown: done");
}

/*
 * nativeTcpWrite(pcb: Long, data: ByteArray, offset: Int, length: Int): Int
 */
JNIEXPORT jint JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTcpWrite(JNIEnv *env, jobject thiz,
                                                           jlong pcb, jbyteArray data,
                                                           jint offset, jint length) {
    (void)thiz;

    if (data == NULL || length <= 0) {
        LOGW("nativeTcpWrite: invalid arguments");
        return -1;
    }

    jbyte *buf = (*env)->GetByteArrayElements(env, data, NULL);
    if (buf == NULL) {
        LOGE("nativeTcpWrite: GetByteArrayElements failed");
        return -1;
    }

    int result = lwip_bridge_tcp_write((void *)(intptr_t)pcb,
                                       (const void *)(buf + offset),
                                       (uint16_t)length);

    (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
    return (jint)result;
}

/*
 * nativeTcpOutput(pcb: Long)
 */
JNIEXPORT void JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTcpOutput(JNIEnv *env, jobject thiz,
                                                            jlong pcb) {
    (void)env;
    (void)thiz;
    lwip_bridge_tcp_output((void *)(intptr_t)pcb);
}

/*
 * nativeTcpRecved(pcb: Long, length: Int)
 */
JNIEXPORT void JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTcpRecved(JNIEnv *env, jobject thiz,
                                                            jlong pcb, jint length) {
    (void)env;
    (void)thiz;
    lwip_bridge_tcp_recved((void *)(intptr_t)pcb, (uint16_t)length);
}

/*
 * nativeTcpClose(pcb: Long)
 */
JNIEXPORT void JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTcpClose(JNIEnv *env, jobject thiz,
                                                           jlong pcb) {
    (void)env;
    (void)thiz;
    lwip_bridge_tcp_close((void *)(intptr_t)pcb);
}

/*
 * nativeTcpAbort(pcb: Long)
 */
JNIEXPORT void JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTcpAbort(JNIEnv *env, jobject thiz,
                                                           jlong pcb) {
    (void)env;
    (void)thiz;
    lwip_bridge_tcp_abort((void *)(intptr_t)pcb);
}

/*
 * nativeTcpSndbuf(pcb: Long): Int
 */
JNIEXPORT jint JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeTcpSndbuf(JNIEnv *env, jobject thiz,
                                                            jlong pcb) {
    (void)env;
    (void)thiz;
    return (jint)lwip_bridge_tcp_sndbuf((void *)(intptr_t)pcb);
}

/*
 * nativeUdpSendto(srcIp: ByteArray, srcPort: Int, dstIp: ByteArray,
 *                 dstPort: Int, isIpv6: Boolean, data: ByteArray, length: Int)
 */
JNIEXPORT void JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeUdpSendto(JNIEnv *env, jobject thiz,
                                                            jbyteArray srcIp, jint srcPort,
                                                            jbyteArray dstIp, jint dstPort,
                                                            jboolean isIpv6,
                                                            jbyteArray data, jint length) {
    (void)thiz;

    if (srcIp == NULL || dstIp == NULL || data == NULL || length <= 0) {
        LOGW("nativeUdpSendto: invalid arguments");
        return;
    }

    jbyte *src_ip_buf = (*env)->GetByteArrayElements(env, srcIp, NULL);
    jbyte *dst_ip_buf = (*env)->GetByteArrayElements(env, dstIp, NULL);
    jbyte *data_buf   = (*env)->GetByteArrayElements(env, data,  NULL);

    if (src_ip_buf == NULL || dst_ip_buf == NULL || data_buf == NULL) {
        LOGE("nativeUdpSendto: GetByteArrayElements failed");
        if (src_ip_buf) (*env)->ReleaseByteArrayElements(env, srcIp, src_ip_buf, JNI_ABORT);
        if (dst_ip_buf) (*env)->ReleaseByteArrayElements(env, dstIp, dst_ip_buf, JNI_ABORT);
        if (data_buf)   (*env)->ReleaseByteArrayElements(env, data,  data_buf,   JNI_ABORT);
        return;
    }

    lwip_bridge_udp_sendto((const void *)src_ip_buf, (uint16_t)srcPort,
                           (const void *)dst_ip_buf, (uint16_t)dstPort,
                           (int)(isIpv6 != JNI_FALSE),
                           (const void *)data_buf, (int)length);

    (*env)->ReleaseByteArrayElements(env, srcIp, src_ip_buf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, dstIp, dst_ip_buf, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, data,  data_buf,   JNI_ABORT);
}

/*
 * nativeIpToString(addr: ByteArray, isIpv6: Boolean): String?
 */
JNIEXPORT jstring JNICALL
Java_com_argsment_anywhere_vpn_NativeBridge_nativeIpToString(JNIEnv *env, jobject thiz,
                                                             jbyteArray addr,
                                                             jboolean isIpv6) {
    (void)thiz;

    if (addr == NULL) {
        LOGW("nativeIpToString: addr is null");
        return NULL;
    }

    jbyte *addr_buf = (*env)->GetByteArrayElements(env, addr, NULL);
    if (addr_buf == NULL) {
        LOGE("nativeIpToString: GetByteArrayElements failed");
        return NULL;
    }

    /* INET6_ADDRSTRLEN is 46 */
    char out[46];
    const char *result = lwip_ip_to_string((const void *)addr_buf,
                                           (int)(isIpv6 != JNI_FALSE),
                                           out, sizeof(out));

    (*env)->ReleaseByteArrayElements(env, addr, addr_buf, JNI_ABORT);

    if (result == NULL) {
        return NULL;
    }

    return (*env)->NewStringUTF(env, out);
}
