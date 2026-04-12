//
//  quic_jni_bridge.c — JNI surface for ngtcp2.
//
//  The C side owns an AndroidQuicConn holding ngtcp2 state and references to
//  the Kotlin QuicBridge.Callbacks object. All ngtcp2 APIs that Kotlin needs
//  are wrapped as `Java_com_argsment_anywhere_vpn_quic_QuicBridge_native*`.
//  Callbacks from ngtcp2 into Kotlin go through cached jmethodIDs on the
//  Callbacks interface.
//

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "ngtcp2/ngtcp2_bridge.h"
#include "ngtcp2/shared.h"

#include <android/log.h>
#define QLOG(tag, ...) __android_log_print(ANDROID_LOG_INFO, tag, __VA_ARGS__)
#define QLOGW(tag, ...) __android_log_print(ANDROID_LOG_WARN, tag, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/*  Cached JVM + method IDs                                            */
/* ------------------------------------------------------------------ */

static JavaVM *g_jvm = NULL;

static jclass  g_cbClass = NULL;

/* Kotlin callback methods on QuicBridge.NativeCallbacks */
static jmethodID g_mBuildClientHello = NULL;       /* (jbyteArray transportParams) -> jbyteArray */
static jmethodID g_mProcessCryptoData = NULL;      /* (int level, jbyteArray data) -> int */
static jmethodID g_mOnStreamData = NULL;           /* (long streamId, byte[] data, boolean fin) */
static jmethodID g_mOnAckedStreamData = NULL;      /* (long streamId, long offset, long datalen) */
static jmethodID g_mOnStreamClose = NULL;          /* (long streamId, long appErrorCode) */
static jmethodID g_mOnRecvDatagram = NULL;         /* (byte[] data) */
static jmethodID g_mOnHandshakeCompleted = NULL;   /* () */
static jmethodID g_mSendUdpPacket = NULL;          /* (byte[] pkt) */

static jbyteArray new_byte_array(JNIEnv *env, const uint8_t *data, size_t len) {
    jbyteArray arr = (*env)->NewByteArray(env, (jsize)len);
    if (!arr) return NULL;
    if (len > 0) {
        (*env)->SetByteArrayRegion(env, arr, 0, (jsize)len, (const jbyte *)data);
    }
    return arr;
}

static JNIEnv *attach_env(int *already_attached) {
    JNIEnv *env = NULL;
    if (!g_jvm) { *already_attached = 0; return NULL; }
    int st = (*g_jvm)->GetEnv(g_jvm, (void **)&env, JNI_VERSION_1_6);
    if (st == JNI_OK) { *already_attached = 1; return env; }
    if (st == JNI_EDETACHED) {
        if ((*g_jvm)->AttachCurrentThread(g_jvm, &env, NULL) == JNI_OK) {
            *already_attached = 0;
            return env;
        }
    }
    return NULL;
}

static void detach_env(int already_attached) {
    if (!already_attached && g_jvm) {
        (*g_jvm)->DetachCurrentThread(g_jvm);
    }
}

/* ------------------------------------------------------------------ */
/*  AndroidQuicConn — per-connection ngtcp2 state                      */
/* ------------------------------------------------------------------ */

typedef struct {
    ngtcp2_conn *conn;
    ngtcp2_cid   dcid;
    ngtcp2_cid   scid;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    socklen_t    addr_len;

    /* Global reference to the Kotlin NativeCallbacks instance. */
    jobject      callbacks;

    /* Stored by callbacks so ngtcp2 can find us from user_data. */
    ngtcp2_crypto_conn_ref conn_ref;

    int          datagrams_enabled;
} AndroidQuicConn;

static AndroidQuicConn *conn_from_user_data(void *ud) {
    if (!ud) return NULL;
    ngtcp2_crypto_conn_ref *ref = (ngtcp2_crypto_conn_ref *)ud;
    return (AndroidQuicConn *)ref->user_data;
}

/* ngtcp2_crypto_conn_ref.get_conn callback */
static ngtcp2_conn *get_conn_cb(ngtcp2_crypto_conn_ref *ref) {
    AndroidQuicConn *c = (AndroidQuicConn *)ref->user_data;
    return c ? c->conn : NULL;
}

static ngtcp2_tstamp now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * 1000000000ULL + (ngtcp2_tstamp)ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/*  ngtcp2 callbacks                                                    */
/* ------------------------------------------------------------------ */

static int cb_client_initial(ngtcp2_conn *conn, void *ud) {
    const ngtcp2_cid *dcid = ngtcp2_conn_get_client_initial_dcid(conn);
    if (!dcid) return NGTCP2_ERR_CALLBACK_FAILURE;
    if (ngtcp2_crypto_derive_and_install_initial_key(
            conn, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NGTCP2_PROTO_VER_V1, dcid) != 0) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    AndroidQuicConn *c = conn_from_user_data(ud);
    if (!c || !c->callbacks) return NGTCP2_ERR_CALLBACK_FAILURE;

    uint8_t pb[256];
    ngtcp2_ssize pLen = ngtcp2_conn_encode_local_transport_params(conn, pb, sizeof(pb));
    if (pLen < 0) return NGTCP2_ERR_CALLBACK_FAILURE;

    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return NGTCP2_ERR_CALLBACK_FAILURE;

    jbyteArray tp = new_byte_array(env, pb, (size_t)pLen);
    if (!tp) { detach_env(attached); return NGTCP2_ERR_CALLBACK_FAILURE; }

    jbyteArray ch = (jbyteArray)(*env)->CallObjectMethod(env, c->callbacks,
                                                         g_mBuildClientHello, tp);
    (*env)->DeleteLocalRef(env, tp);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        detach_env(attached);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if (!ch) { detach_env(attached); return NGTCP2_ERR_CALLBACK_FAILURE; }

    jsize chlen = (*env)->GetArrayLength(env, ch);
    jbyte *chp = (*env)->GetByteArrayElements(env, ch, NULL);
    int rv = ngtcp2_conn_submit_crypto_data(conn, NGTCP2_ENCRYPTION_LEVEL_INITIAL,
                                            (const uint8_t *)chp, (size_t)chlen);
    (*env)->ReleaseByteArrayElements(env, ch, chp, JNI_ABORT);
    (*env)->DeleteLocalRef(env, ch);
    detach_env(attached);
    return rv;
}

static int cb_recv_crypto_data(ngtcp2_conn *conn, ngtcp2_encryption_level level,
                               uint64_t offset, const uint8_t *data, size_t datalen,
                               void *ud) {
    (void)conn; (void)offset;
    if (!data || datalen == 0) return 0;
    AndroidQuicConn *c = conn_from_user_data(ud);
    if (!c || !c->callbacks) return NGTCP2_ERR_CALLBACK_FAILURE;

    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return NGTCP2_ERR_CALLBACK_FAILURE;

    jbyteArray arr = new_byte_array(env, data, datalen);
    if (!arr) { detach_env(attached); return NGTCP2_ERR_CALLBACK_FAILURE; }
    jint rv = (*env)->CallIntMethod(env, c->callbacks, g_mProcessCryptoData,
                                    (jint)level, arr);
    (*env)->DeleteLocalRef(env, arr);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        detach_env(attached);
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    detach_env(attached);
    return rv;
}

static int cb_recv_stream_data(ngtcp2_conn *conn, uint32_t flags, int64_t sid,
                               uint64_t offset, const uint8_t *data, size_t datalen,
                               void *ud, void *stream_ud) {
    (void)conn; (void)offset; (void)stream_ud;
    AndroidQuicConn *c = conn_from_user_data(ud);
    if (!c || !c->callbacks) return 0;

    int fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return 0;

    jbyteArray arr = new_byte_array(env, data, datalen);
    (*env)->CallVoidMethod(env, c->callbacks, g_mOnStreamData,
                           (jlong)sid, arr, (jboolean)(fin ? JNI_TRUE : JNI_FALSE));
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (arr) (*env)->DeleteLocalRef(env, arr);
    detach_env(attached);
    return 0;
}

static int cb_acked_stream_data_offset(ngtcp2_conn *conn, int64_t sid, uint64_t offset,
                                       uint64_t datalen, void *ud, void *stream_ud) {
    (void)conn; (void)stream_ud;
    AndroidQuicConn *c = conn_from_user_data(ud);
    if (!c || !c->callbacks) return 0;
    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return 0;
    (*env)->CallVoidMethod(env, c->callbacks, g_mOnAckedStreamData,
                           (jlong)sid, (jlong)offset, (jlong)datalen);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    detach_env(attached);
    return 0;
}

static int cb_stream_close(ngtcp2_conn *conn, uint32_t flags, int64_t sid,
                           uint64_t app_err, void *ud, void *stream_ud) {
    (void)conn; (void)flags; (void)stream_ud;
    AndroidQuicConn *c = conn_from_user_data(ud);
    if (!c || !c->callbacks) return 0;
    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return 0;
    (*env)->CallVoidMethod(env, c->callbacks, g_mOnStreamClose,
                           (jlong)sid, (jlong)app_err);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    detach_env(attached);
    return 0;
}

static void cb_rand(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rc) {
    (void)rc;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        size_t remaining = destlen;
        uint8_t *p = dest;
        while (remaining > 0) {
            ssize_t n = read(fd, p, remaining);
            if (n <= 0) { if (errno == EINTR) continue; break; }
            p += n; remaining -= (size_t)n;
        }
        close(fd);
    }
}

static int cb_get_new_connection_id(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                    ngtcp2_stateless_reset_token *token,
                                    size_t cidlen, void *ud) {
    (void)conn; (void)ud;
    if (!cid || !token) return NGTCP2_ERR_CALLBACK_FAILURE;
    cid->datalen = cidlen;
    cb_rand(cid->data, cidlen, NULL);
    cb_rand(token->data, sizeof(token->data), NULL);
    return 0;
}

static int cb_handshake_completed(ngtcp2_conn *conn, void *ud) {
    (void)conn;
    AndroidQuicConn *c = conn_from_user_data(ud);
    if (!c || !c->callbacks) return 0;
    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return 0;
    (*env)->CallVoidMethod(env, c->callbacks, g_mOnHandshakeCompleted);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    detach_env(attached);
    return 0;
}

static int cb_recv_datagram(ngtcp2_conn *conn, uint32_t flags,
                            const uint8_t *data, size_t datalen, void *ud) {
    (void)conn; (void)flags;
    AndroidQuicConn *c = conn_from_user_data(ud);
    if (!c || !c->callbacks || !data || datalen == 0) return 0;
    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return 0;
    jbyteArray arr = new_byte_array(env, data, datalen);
    (*env)->CallVoidMethod(env, c->callbacks, g_mOnRecvDatagram, arr);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (arr) (*env)->DeleteLocalRef(env, arr);
    detach_env(attached);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Kotlin-side crypto callback shims                                   */
/* ------------------------------------------------------------------ */

/* AEAD/HMAC/AES-ECB are registered from Kotlin as global-function pointers via
   a "trampoline" scheme: we hold jmethodIDs to static crypto methods on
   QuicBridge.NativeCrypto, and each ngtcp2 crypto callback calls the JVM. The
   cost is ~1µs per call which is fine except for per-packet AEAD. To minimize
   overhead, AEAD uses the JVM's javax.crypto.Cipher under pooled reuse. */

static jclass      g_cryptoClass = NULL;
static jmethodID   g_mAeadEncrypt = NULL;   /* static byte[] (key, nonce, pt, aad, type) */
static jmethodID   g_mAeadDecrypt = NULL;   /* static byte[] (key, nonce, ct, aad, type) */
static jmethodID   g_mHmac        = NULL;   /* static byte[] (key, data, mdType) */
static jmethodID   g_mAesEcb      = NULL;   /* static byte[] (key, block) */
static jmethodID   g_mChachaHp    = NULL;   /* static byte[] (key, sample) */

static int crypto_aead_encrypt_c(uint8_t *dest, const uint8_t *key, size_t keylen,
                                 const uint8_t *nonce, size_t noncelen,
                                 const uint8_t *pt, size_t ptlen,
                                 const uint8_t *aad, size_t aadlen, int type) {
    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return -1;
    jbyteArray jkey = new_byte_array(env, key, keylen);
    jbyteArray jnonce = new_byte_array(env, nonce, noncelen);
    jbyteArray jpt = new_byte_array(env, pt, ptlen);
    jbyteArray jaad = new_byte_array(env, aad, aadlen);
    jbyteArray out = (jbyteArray)(*env)->CallStaticObjectMethod(
        env, g_cryptoClass, g_mAeadEncrypt, jkey, jnonce, jpt, jaad, (jint)type);
    int rv = -1;
    if (!(*env)->ExceptionCheck(env) && out) {
        jsize outlen = (*env)->GetArrayLength(env, out);
        if ((size_t)outlen == ptlen + 16) {
            (*env)->GetByteArrayRegion(env, out, 0, outlen, (jbyte *)dest);
            rv = 0;
        }
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (out) (*env)->DeleteLocalRef(env, out);
    if (jkey) (*env)->DeleteLocalRef(env, jkey);
    if (jnonce) (*env)->DeleteLocalRef(env, jnonce);
    if (jpt) (*env)->DeleteLocalRef(env, jpt);
    if (jaad) (*env)->DeleteLocalRef(env, jaad);
    detach_env(attached);
    return rv;
}

static int crypto_aead_decrypt_c(uint8_t *dest, const uint8_t *key, size_t keylen,
                                 const uint8_t *nonce, size_t noncelen,
                                 const uint8_t *ct, size_t ctlen,
                                 const uint8_t *aad, size_t aadlen, int type) {
    if (ctlen < 16) return -1;
    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return -1;
    jbyteArray jkey = new_byte_array(env, key, keylen);
    jbyteArray jnonce = new_byte_array(env, nonce, noncelen);
    jbyteArray jct = new_byte_array(env, ct, ctlen);
    jbyteArray jaad = new_byte_array(env, aad, aadlen);
    jbyteArray out = (jbyteArray)(*env)->CallStaticObjectMethod(
        env, g_cryptoClass, g_mAeadDecrypt, jkey, jnonce, jct, jaad, (jint)type);
    int rv = -1;
    if (!(*env)->ExceptionCheck(env) && out) {
        jsize outlen = (*env)->GetArrayLength(env, out);
        if ((size_t)outlen == ctlen - 16) {
            (*env)->GetByteArrayRegion(env, out, 0, outlen, (jbyte *)dest);
            rv = 0;
        }
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (out) (*env)->DeleteLocalRef(env, out);
    if (jkey) (*env)->DeleteLocalRef(env, jkey);
    if (jnonce) (*env)->DeleteLocalRef(env, jnonce);
    if (jct) (*env)->DeleteLocalRef(env, jct);
    if (jaad) (*env)->DeleteLocalRef(env, jaad);
    detach_env(attached);
    return rv;
}

static int crypto_hmac_c(uint8_t *dest, const uint8_t *key, size_t keylen,
                         const uint8_t *data, size_t datalen, int md_type) {
    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return -1;
    jbyteArray jkey = new_byte_array(env, key, keylen);
    jbyteArray jdata = new_byte_array(env, data, datalen);
    jbyteArray out = (jbyteArray)(*env)->CallStaticObjectMethod(
        env, g_cryptoClass, g_mHmac, jkey, jdata, (jint)md_type);
    int rv = -1;
    if (!(*env)->ExceptionCheck(env) && out) {
        jsize outlen = (*env)->GetArrayLength(env, out);
        if (outlen == 32 || outlen == 48) {
            (*env)->GetByteArrayRegion(env, out, 0, outlen, (jbyte *)dest);
            rv = 0;
        }
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (out) (*env)->DeleteLocalRef(env, out);
    if (jkey) (*env)->DeleteLocalRef(env, jkey);
    if (jdata) (*env)->DeleteLocalRef(env, jdata);
    detach_env(attached);
    return rv;
}

static int crypto_aes_ecb_c(uint8_t *dest, const uint8_t *key, size_t keylen,
                            const uint8_t *block) {
    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return -1;
    jbyteArray jkey = new_byte_array(env, key, keylen);
    jbyteArray jblock = new_byte_array(env, block, 16);
    jbyteArray out = (jbyteArray)(*env)->CallStaticObjectMethod(
        env, g_cryptoClass, g_mAesEcb, jkey, jblock);
    int rv = -1;
    if (!(*env)->ExceptionCheck(env) && out) {
        jsize outlen = (*env)->GetArrayLength(env, out);
        if (outlen == 16) {
            (*env)->GetByteArrayRegion(env, out, 0, 16, (jbyte *)dest);
            rv = 0;
        }
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (out) (*env)->DeleteLocalRef(env, out);
    if (jkey) (*env)->DeleteLocalRef(env, jkey);
    if (jblock) (*env)->DeleteLocalRef(env, jblock);
    detach_env(attached);
    return rv;
}

static int crypto_chacha20_hp_c(uint8_t *dest, const uint8_t *key, size_t keylen,
                                const uint8_t *sample) {
    int attached;
    JNIEnv *env = attach_env(&attached);
    if (!env) return -1;
    jbyteArray jkey = new_byte_array(env, key, keylen);
    jbyteArray jsample = new_byte_array(env, sample, 16);
    jbyteArray out = (jbyteArray)(*env)->CallStaticObjectMethod(
        env, g_cryptoClass, g_mChachaHp, jkey, jsample);
    int rv = -1;
    if (!(*env)->ExceptionCheck(env) && out) {
        jsize outlen = (*env)->GetArrayLength(env, out);
        if (outlen == 5) {
            (*env)->GetByteArrayRegion(env, out, 0, 5, (jbyte *)dest);
            rv = 0;
        }
    }
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if (out) (*env)->DeleteLocalRef(env, out);
    if (jkey) (*env)->DeleteLocalRef(env, jkey);
    if (jsample) (*env)->DeleteLocalRef(env, jsample);
    detach_env(attached);
    return rv;
}

/* ------------------------------------------------------------------ */
/*  JNI entry points                                                    */
/* ------------------------------------------------------------------ */

#define JNI_FN(name) Java_com_argsment_anywhere_vpn_quic_QuicBridge_##name

JNIEXPORT void JNICALL
JNI_FN(nativeInstall)(JNIEnv *env, jclass cls, jclass callbacksClass,
                      jclass cryptoClass) {
    (void)cls;
    if (!g_jvm) (*env)->GetJavaVM(env, &g_jvm);

    if (g_cbClass) (*env)->DeleteGlobalRef(env, g_cbClass);
    g_cbClass = (jclass)(*env)->NewGlobalRef(env, callbacksClass);
    g_mBuildClientHello     = (*env)->GetMethodID(env, g_cbClass, "buildClientHello", "([B)[B");
    g_mProcessCryptoData    = (*env)->GetMethodID(env, g_cbClass, "processCryptoData", "(I[B)I");
    g_mOnStreamData         = (*env)->GetMethodID(env, g_cbClass, "onStreamData",     "(J[BZ)V");
    g_mOnAckedStreamData    = (*env)->GetMethodID(env, g_cbClass, "onAckedStreamData","(JJJ)V");
    g_mOnStreamClose        = (*env)->GetMethodID(env, g_cbClass, "onStreamClose",    "(JJ)V");
    g_mOnRecvDatagram       = (*env)->GetMethodID(env, g_cbClass, "onRecvDatagram",   "([B)V");
    g_mOnHandshakeCompleted = (*env)->GetMethodID(env, g_cbClass, "onHandshakeCompleted","()V");
    g_mSendUdpPacket        = (*env)->GetMethodID(env, g_cbClass, "sendUdpPacket",    "([B)V");

    if (g_cryptoClass) (*env)->DeleteGlobalRef(env, g_cryptoClass);
    g_cryptoClass = (jclass)(*env)->NewGlobalRef(env, cryptoClass);
    g_mAeadEncrypt = (*env)->GetStaticMethodID(env, g_cryptoClass, "aeadEncrypt", "([B[B[B[BI)[B");
    g_mAeadDecrypt = (*env)->GetStaticMethodID(env, g_cryptoClass, "aeadDecrypt", "([B[B[B[BI)[B");
    g_mHmac        = (*env)->GetStaticMethodID(env, g_cryptoClass, "hmac",        "([B[BI)[B");
    g_mAesEcb      = (*env)->GetStaticMethodID(env, g_cryptoClass, "aesEcb",      "([B[B)[B");
    g_mChachaHp    = (*env)->GetStaticMethodID(env, g_cryptoClass, "chacha20Hp",  "([B[B)[B");

    ngtcp2_crypto_android_set_callbacks(crypto_aead_encrypt_c, crypto_aead_decrypt_c,
                                        crypto_hmac_c, crypto_aes_ecb_c,
                                        crypto_chacha20_hp_c);
}

static void fill_random(uint8_t *dest, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        size_t rem = len; uint8_t *p = dest;
        while (rem > 0) {
            ssize_t n = read(fd, p, rem);
            if (n <= 0) { if (errno == EINTR) continue; break; }
            p += n; rem -= (size_t)n;
        }
        close(fd);
    }
}

JNIEXPORT jlong JNICALL
JNI_FN(nativeCreate)(JNIEnv *env, jclass cls, jobject callbacks,
                     jstring jhost, jint jport, jboolean ipv6,
                     jbyteArray hostAddrBytes, jboolean datagramsEnabled) {
    (void)cls; (void)jhost;
    AndroidQuicConn *c = calloc(1, sizeof(*c));
    if (!c) return 0;

    c->callbacks = (*env)->NewGlobalRef(env, callbacks);
    c->datagrams_enabled = datagramsEnabled ? 1 : 0;

    /* Build remote address from hostAddrBytes (4 or 16 bytes, network order). */
    jsize alen = (*env)->GetArrayLength(env, hostAddrBytes);
    jbyte *abytes = (*env)->GetByteArrayElements(env, hostAddrBytes, NULL);

    if (ipv6 && alen == 16) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&c->remote_addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)jport);
        memcpy(&sin6->sin6_addr, abytes, 16);
        c->addr_len = (socklen_t)sizeof(*sin6);

        struct sockaddr_in6 *ls = (struct sockaddr_in6 *)&c->local_addr;
        ls->sin6_family = AF_INET6;
    } else if (!ipv6 && alen == 4) {
        struct sockaddr_in *sin = (struct sockaddr_in *)&c->remote_addr;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)jport);
        memcpy(&sin->sin_addr, abytes, 4);
        c->addr_len = (socklen_t)sizeof(*sin);

        struct sockaddr_in *ls = (struct sockaddr_in *)&c->local_addr;
        ls->sin_family = AF_INET;
    } else {
        (*env)->ReleaseByteArrayElements(env, hostAddrBytes, abytes, JNI_ABORT);
        (*env)->DeleteGlobalRef(env, c->callbacks);
        free(c);
        return 0;
    }
    (*env)->ReleaseByteArrayElements(env, hostAddrBytes, abytes, JNI_ABORT);

    /* Generate connection IDs */
    c->dcid.datalen = 16;
    fill_random(c->dcid.data, 16);
    c->scid.datalen = 16;
    fill_random(c->scid.data, 16);

    /* Configure ngtcp2 */
    ngtcp2_callbacks cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.client_initial             = cb_client_initial;
    cbs.recv_crypto_data           = cb_recv_crypto_data;
    cbs.encrypt                    = ngtcp2_crypto_encrypt_cb;
    cbs.decrypt                    = ngtcp2_crypto_decrypt_cb;
    cbs.hp_mask                    = ngtcp2_crypto_hp_mask_cb;
    cbs.recv_retry                 = ngtcp2_crypto_recv_retry_cb;
    cbs.recv_stream_data           = cb_recv_stream_data;
    cbs.acked_stream_data_offset   = cb_acked_stream_data_offset;
    cbs.stream_close               = cb_stream_close;
    cbs.rand                       = cb_rand;
    cbs.get_new_connection_id2     = cb_get_new_connection_id;
    cbs.update_key                 = ngtcp2_crypto_update_key_cb;
    cbs.delete_crypto_aead_ctx     = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cbs.delete_crypto_cipher_ctx   = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cbs.get_path_challenge_data2   = ngtcp2_crypto_get_path_challenge_data2_cb;
    cbs.version_negotiation        = ngtcp2_crypto_version_negotiation_cb;
    cbs.handshake_completed        = cb_handshake_completed;
    if (c->datagrams_enabled) cbs.recv_datagram = cb_recv_datagram;

    ngtcp2_settings settings;
    ngtcp2_swift_settings_default(&settings);
    settings.initial_ts = now_ns();
    settings.max_tx_udp_payload_size = 1452;

    ngtcp2_transport_params params;
    ngtcp2_swift_transport_params_default(&params);
    params.initial_max_streams_bidi = 100;
    params.initial_max_streams_uni = 100;
    params.initial_max_data = 64ULL * 1024 * 1024;
    params.initial_max_stream_data_bidi_local = 64ULL * 1024 * 1024;
    params.initial_max_stream_data_bidi_remote = 64ULL * 1024 * 1024;
    params.initial_max_stream_data_uni = 64ULL * 1024 * 1024;
    params.max_idle_timeout = 30ULL * 1000000000ULL;
    params.disable_active_migration = 1;
    if (c->datagrams_enabled) params.max_datagram_frame_size = 65535;

    ngtcp2_path path;
    path.local.addr = (struct sockaddr *)&c->local_addr;
    path.local.addrlen = c->addr_len;
    path.remote.addr = (struct sockaddr *)&c->remote_addr;
    path.remote.addrlen = c->addr_len;
    path.user_data = NULL;

    c->conn_ref.user_data = c;
    c->conn_ref.get_conn = get_conn_cb;

    int rv = ngtcp2_swift_conn_client_new(&c->conn, &c->dcid, &c->scid, &path,
                                          NGTCP2_PROTO_VER_V1, &cbs, &settings,
                                          &params, NULL, &c->conn_ref);
    if (rv != 0 || !c->conn) {
        (*env)->DeleteGlobalRef(env, c->callbacks);
        free(c);
        return 0;
    }

    /* Signal the cipher suite to ngtcp2 (initial only; updated when TLS handshake
       settles on a concrete suite). */
    ngtcp2_conn_set_tls_native_handle(c->conn,
        (void *)(uintptr_t)NGTCP2_APPLE_CS_AES_128_GCM_SHA256);
    return (jlong)(intptr_t)c;
}

JNIEXPORT void JNICALL
JNI_FN(nativeDestroy)(JNIEnv *env, jclass cls, jlong handle) {
    (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c) return;
    if (c->conn) { ngtcp2_conn_del(c->conn); c->conn = NULL; }
    if (c->callbacks) { (*env)->DeleteGlobalRef(env, c->callbacks); c->callbacks = NULL; }
    free(c);
}

JNIEXPORT jlong JNICALL
JNI_FN(nativeOpenBidiStream)(JNIEnv *env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn) return -1;
    int64_t sid = -1;
    if (ngtcp2_conn_open_bidi_stream(c->conn, &sid, NULL) != 0) return -1;
    return (jlong)sid;
}

JNIEXPORT jlong JNICALL
JNI_FN(nativeOpenUniStream)(JNIEnv *env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn) return -1;
    int64_t sid = -1;
    if (ngtcp2_conn_open_uni_stream(c->conn, &sid, NULL) != 0) return -1;
    return (jlong)sid;
}

JNIEXPORT void JNICALL
JNI_FN(nativeExtendStreamOffset)(JNIEnv *env, jclass cls, jlong handle,
                                 jlong sid, jlong count) {
    (void)env; (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn || count <= 0) return;
    ngtcp2_conn_extend_max_stream_offset(c->conn, (int64_t)sid, (uint64_t)count);
    ngtcp2_conn_extend_max_offset(c->conn, (uint64_t)count);
}

JNIEXPORT jint JNICALL
JNI_FN(nativeShutdownStream)(JNIEnv *env, jclass cls, jlong handle,
                             jlong sid, jlong appErrCode) {
    (void)env; (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn) return -1;
    return (jint)ngtcp2_conn_shutdown_stream(c->conn, 0, (int64_t)sid, (uint64_t)appErrCode);
}

/* Writes as many packets as ngtcp2 has ready to send.
   Returns via g_mSendUdpPacket calls on the Kotlin side. */
JNIEXPORT jint JNICALL
JNI_FN(nativeWriteLoop)(JNIEnv *env, jclass cls, jlong handle,
                       jlong sid, jbyteArray jdata, jboolean fin) {
    (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn) return -1;

    const size_t MAX_PAY = 1452;
    uint8_t pkt[1500];
    ngtcp2_pkt_info pi;
    memset(&pi, 0, sizeof(pi));

    size_t dataLen = 0;
    jbyte *dataPtr = NULL;
    if (jdata) {
        dataLen = (size_t)(*env)->GetArrayLength(env, jdata);
        dataPtr = (*env)->GetByteArrayElements(env, jdata, NULL);
    }

    ngtcp2_tstamp ts = now_ns();
    size_t consumed = 0;
    int stream_pending = (jdata != NULL && dataLen > 0) || fin;

    while (1) {
        ngtcp2_ssize pdatalen = 0;
        ngtcp2_ssize nwrite;
        if (stream_pending) {
            uint32_t flags = 0;
            if (fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            ngtcp2_vec vec;
            vec.base = (uint8_t *)(dataPtr + consumed);
            vec.len = dataLen - consumed;
            nwrite = ngtcp2_swift_conn_writev_stream(c->conn, NULL, &pi, pkt, MAX_PAY,
                                                     &pdatalen, flags, (int64_t)sid,
                                                     &vec, 1, ts);
            if (nwrite < 0) {
                if (nwrite == NGTCP2_ERR_WRITE_MORE) {
                    if (pdatalen > 0) consumed += (size_t)pdatalen;
                    continue;
                }
                if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
                    if (pdatalen > 0) consumed += (size_t)pdatalen;
                    stream_pending = 0;
                    continue;
                }
                break;
            }
            if (pdatalen > 0) consumed += (size_t)pdatalen;
            if (consumed >= dataLen && !fin) stream_pending = 0;
            if (nwrite == 0) {
                stream_pending = 0;
                continue;
            }
        } else {
            nwrite = ngtcp2_swift_conn_write_pkt(c->conn, NULL, &pi, pkt, MAX_PAY, ts);
            if (nwrite <= 0) break;
        }

        jbyteArray outPkt = new_byte_array(env, pkt, (size_t)nwrite);
        if (outPkt) {
            (*env)->CallVoidMethod(env, c->callbacks, g_mSendUdpPacket, outPkt);
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, outPkt);
        }
    }

    if (dataPtr) (*env)->ReleaseByteArrayElements(env, jdata, dataPtr, JNI_ABORT);
    return (jint)consumed;
}

JNIEXPORT jint JNICALL
JNI_FN(nativeReadPacket)(JNIEnv *env, jclass cls, jlong handle, jbyteArray pkt) {
    (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn || !pkt) return -1;

    jsize len = (*env)->GetArrayLength(env, pkt);
    jbyte *buf = (*env)->GetByteArrayElements(env, pkt, NULL);

    ngtcp2_path path;
    path.local.addr = (struct sockaddr *)&c->local_addr;
    path.local.addrlen = c->addr_len;
    path.remote.addr = (struct sockaddr *)&c->remote_addr;
    path.remote.addrlen = c->addr_len;
    path.user_data = NULL;

    ngtcp2_pkt_info pi;
    memset(&pi, 0, sizeof(pi));
    int rv = ngtcp2_swift_conn_read_pkt(c->conn, &path, &pi,
                                        (const uint8_t *)buf, (size_t)len, now_ns());
    (*env)->ReleaseByteArrayElements(env, pkt, buf, JNI_ABORT);
    return (jint)rv;
}

JNIEXPORT jint JNICALL
JNI_FN(nativeWriteDatagram)(JNIEnv *env, jclass cls, jlong handle, jbyteArray dgram) {
    (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn || !dgram) return -1;
    jsize len = (*env)->GetArrayLength(env, dgram);
    jbyte *buf = (*env)->GetByteArrayElements(env, dgram, NULL);

    uint8_t pkt[1500];
    ngtcp2_pkt_info pi; memset(&pi, 0, sizeof(pi));
    int accepted = 0;
    ngtcp2_ssize nwrite = ngtcp2_swift_conn_write_datagram(
        c->conn, NULL, &pi, pkt, sizeof(pkt), &accepted, 0, 0,
        (const uint8_t *)buf, (size_t)len, now_ns());
    (*env)->ReleaseByteArrayElements(env, dgram, buf, JNI_ABORT);
    if (nwrite < 0) return (jint)nwrite;
    if (nwrite > 0) {
        jbyteArray outPkt = new_byte_array(env, pkt, (size_t)nwrite);
        if (outPkt) {
            (*env)->CallVoidMethod(env, c->callbacks, g_mSendUdpPacket, outPkt);
            if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            (*env)->DeleteLocalRef(env, outPkt);
        }
    }
    return accepted ? 0 : -2;
}

JNIEXPORT jlong JNICALL
JNI_FN(nativeGetExpiry)(JNIEnv *env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn) return -1;
    ngtcp2_tstamp e = ngtcp2_conn_get_expiry(c->conn);
    if (e == UINT64_MAX) return -1;
    return (jlong)e;
}

JNIEXPORT jint JNICALL
JNI_FN(nativeHandleExpiry)(JNIEnv *env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn) return -1;
    return (jint)ngtcp2_conn_handle_expiry(c->conn, now_ns());
}

JNIEXPORT jlong JNICALL
JNI_FN(nativeMaxDatagramPayload)(JNIEnv *env, jclass cls, jlong handle) {
    (void)env; (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn) return 0;
    const ngtcp2_transport_params *p = ngtcp2_swift_conn_get_remote_transport_params(c->conn);
    if (!p || p->max_datagram_frame_size == 0) return 0;
    int64_t v = (int64_t)p->max_datagram_frame_size - 9;
    return v > 0 ? v : 0;
}

/* Installs the cipher suite selected by the Kotlin TLS handshake so that
   ngtcp2's crypto context derives handshake/1-RTT keys with the right AEAD+MD. */
JNIEXPORT void JNICALL
JNI_FN(nativeSetTlsCipherSuite)(JNIEnv *env, jclass cls, jlong handle, jint suite) {
    (void)env; (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn) return;
    ngtcp2_conn_set_tls_native_handle(c->conn, (void *)(uintptr_t)suite);
}

JNIEXPORT jint JNICALL
JNI_FN(nativeSubmitCryptoData)(JNIEnv *env, jclass cls, jlong handle,
                               jint level, jbyteArray data) {
    (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn || !data) return -1;
    jsize len = (*env)->GetArrayLength(env, data);
    jbyte *buf = (*env)->GetByteArrayElements(env, data, NULL);
    int rv = ngtcp2_conn_submit_crypto_data(c->conn, (ngtcp2_encryption_level)level,
                                            (const uint8_t *)buf, (size_t)len);
    (*env)->ReleaseByteArrayElements(env, data, buf, JNI_ABORT);
    return (jint)rv;
}

JNIEXPORT jint JNICALL
JNI_FN(nativeInstallHandshakeKeys)(JNIEnv *env, jclass cls, jlong handle,
                                   jbyteArray rxSecret, jbyteArray txSecret) {
    (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn) return -1;
    jsize rxLen = (*env)->GetArrayLength(env, rxSecret);
    jsize txLen = (*env)->GetArrayLength(env, txSecret);
    if (rxLen != txLen) return -1;
    jbyte *rx = (*env)->GetByteArrayElements(env, rxSecret, NULL);
    jbyte *tx = (*env)->GetByteArrayElements(env, txSecret, NULL);
    int rv = ngtcp2_crypto_derive_and_install_rx_key(c->conn, NULL, NULL, NULL,
                                                      NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                                      (const uint8_t *)rx, (size_t)rxLen);
    if (rv == 0) {
        rv = ngtcp2_crypto_derive_and_install_tx_key(c->conn, NULL, NULL, NULL,
                                                      NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE,
                                                      (const uint8_t *)tx, (size_t)txLen);
    }
    (*env)->ReleaseByteArrayElements(env, rxSecret, rx, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, txSecret, tx, JNI_ABORT);
    return (jint)rv;
}

JNIEXPORT jint JNICALL
JNI_FN(nativeInstallApplicationKeys)(JNIEnv *env, jclass cls, jlong handle,
                                     jbyteArray rxSecret, jbyteArray txSecret) {
    (void)cls;
    AndroidQuicConn *c = (AndroidQuicConn *)(intptr_t)handle;
    if (!c || !c->conn) return -1;
    jsize rxLen = (*env)->GetArrayLength(env, rxSecret);
    jsize txLen = (*env)->GetArrayLength(env, txSecret);
    if (rxLen != txLen) return -1;
    jbyte *rx = (*env)->GetByteArrayElements(env, rxSecret, NULL);
    jbyte *tx = (*env)->GetByteArrayElements(env, txSecret, NULL);
    int rv = ngtcp2_crypto_derive_and_install_rx_key(c->conn, NULL, NULL, NULL,
                                                      NGTCP2_ENCRYPTION_LEVEL_1RTT,
                                                      (const uint8_t *)rx, (size_t)rxLen);
    if (rv == 0) {
        rv = ngtcp2_crypto_derive_and_install_tx_key(c->conn, NULL, NULL, NULL,
                                                      NGTCP2_ENCRYPTION_LEVEL_1RTT,
                                                      (const uint8_t *)tx, (size_t)txLen);
    }
    if (rv == 0) ngtcp2_conn_tls_handshake_completed(c->conn);
    (*env)->ReleaseByteArrayElements(env, rxSecret, rx, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, txSecret, tx, JNI_ABORT);
    return (jint)rv;
}
