/*
 * os/log.h — Apple os_log compatibility shim for Android NDK.
 *
 * Redirects os_log calls to Android's __android_log_print so that
 * lwip_bridge.c compiles unchanged.
 */

#ifndef OS_LOG_H_COMPAT
#define OS_LOG_H_COMPAT

#include <android/log.h>
#include <stdarg.h>

typedef const char* os_log_t;

#define OS_LOG_DEFAULT ((os_log_t)"default")

static inline os_log_t os_log_create(const char *subsystem, const char *category) {
    (void)subsystem;
    return category;
}

/* Variadic logging helper */
static inline void _os_log_impl(os_log_t log, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static inline void _os_log_impl(os_log_t log, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    __android_log_vprint(ANDROID_LOG_ERROR, log ? log : "os_log", fmt, args);
    va_end(args);
}

/* os_log_error maps to Android ERROR level */
#define os_log_error(log, fmt, ...) _os_log_impl(log, fmt, ##__VA_ARGS__)

#define os_log_debug(log, fmt, ...) \
    __android_log_print(ANDROID_LOG_DEBUG, log ? log : "os_log", fmt, ##__VA_ARGS__)

/* os_log maps to Android DEBUG level (unused in bridge, but defined for completeness) */
#define os_log(log, fmt, ...) do { \
    va_list _args; \
    (void)_args; \
    __android_log_print(ANDROID_LOG_DEBUG, log ? log : "os_log", fmt, ##__VA_ARGS__); \
} while(0)

#endif /* OS_LOG_H_COMPAT */
