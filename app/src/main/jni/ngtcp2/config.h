//
//  config.h — Android NDK port
//

#ifndef NGTCP2_CONFIG_H
#define NGTCP2_CONFIG_H

#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_IN_H 1
#define HAVE_UNISTD_H 1

/* Bionic provides endian.h with htobe64/be64toh macros */
#define HAVE_ENDIAN_H 1
#define HAVE_DECL_BE64TOH 1
#define HAVE_DECL_BSWAP_64 0

/* Bionic lacks memset_s; shared.c uses its fallback path */
/* #undef HAVE_MEMSET_S */

/* Bionic ships explicit_bzero on API 21+ */
#define HAVE_EXPLICIT_BZERO 1

/* Not used on Android */
/* #undef HAVE_SYS_ENDIAN_H */
/* #undef HAVE_BYTESWAP_H */
/* #undef HAVE_ASM_TYPES_H */
/* #undef HAVE_LINUX_NETLINK_H */
/* #undef HAVE_LINUX_RTNETLINK_H */

/* Little-endian on all Android-supported ABIs */
/* #undef WORDS_BIGENDIAN */

/* No brotli */
/* #undef HAVE_LIBBROTLI */

/* No debug output */
/* #undef DEBUGBUILD */

#endif /* NGTCP2_CONFIG_H */
