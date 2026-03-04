cmake_minimum_required(VERSION 3.22.1)
project("anywhere_native" C)

# --------------------------------------------------------------------------
# lwIP source files
# --------------------------------------------------------------------------
set(LWIP_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lwip)

set(LWIP_SOURCES
    ${LWIP_DIR}/src/core/init.c
    ${LWIP_DIR}/src/core/def.c
    ${LWIP_DIR}/src/core/ip.c
    ${LWIP_DIR}/src/core/mem.c
    ${LWIP_DIR}/src/core/memp.c
    ${LWIP_DIR}/src/core/netif.c
    ${LWIP_DIR}/src/core/pbuf.c
    ${LWIP_DIR}/src/core/tcp.c
    ${LWIP_DIR}/src/core/tcp_in.c
    ${LWIP_DIR}/src/core/tcp_out.c
    ${LWIP_DIR}/src/core/udp.c
    ${LWIP_DIR}/src/core/inet_chksum.c
    ${LWIP_DIR}/src/core/timeouts.c
    ${LWIP_DIR}/src/core/ipv4/ip4.c
    ${LWIP_DIR}/src/core/ipv4/ip4_addr.c
    ${LWIP_DIR}/src/core/ipv4/ip4_frag.c
    ${LWIP_DIR}/src/core/ipv4/icmp.c
    ${LWIP_DIR}/src/core/ipv6/ip6.c
    ${LWIP_DIR}/src/core/ipv6/ip6_addr.c
    ${LWIP_DIR}/src/core/ipv6/ip6_frag.c
    ${LWIP_DIR}/src/core/ipv6/icmp6.c
    ${LWIP_DIR}/src/core/ipv6/nd6.c
    ${LWIP_DIR}/src/core/ipv6/inet6.c
    ${LWIP_DIR}/port/sys_arch.c
    ${LWIP_DIR}/lwip_bridge.c
)

set(LWIP_INCLUDE_DIRS
    ${LWIP_DIR}/src/include
    ${LWIP_DIR}/port
    ${LWIP_DIR}/port/arch
)

# --------------------------------------------------------------------------
# BLAKE3 source files
# --------------------------------------------------------------------------
set(BLAKE3_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/blake3.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/blake3_dispatch.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/blake3_portable.c
)

# --------------------------------------------------------------------------
# TLS Key Derivation (uses CommonCrypto compat shim)
# --------------------------------------------------------------------------
set(CRYPTO_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto/CTLSKeyDerivation.c
)

# --------------------------------------------------------------------------
# Packet utilities
# --------------------------------------------------------------------------
set(PACKET_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/packet/CPacket.c
)

# --------------------------------------------------------------------------
# GeoIP
# --------------------------------------------------------------------------
set(GEOIP_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/geoip/CGeoIP.c
)

# --------------------------------------------------------------------------
# VLESS
# --------------------------------------------------------------------------
set(VLESS_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/vless/CVLESS.c
)

# --------------------------------------------------------------------------
# libyaml
# --------------------------------------------------------------------------
set(LIBYAML_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libyaml)

set(LIBYAML_SOURCES
    ${LIBYAML_DIR}/src/api.c
    ${LIBYAML_DIR}/src/dumper.c
    ${LIBYAML_DIR}/src/emitter.c
    ${LIBYAML_DIR}/src/loader.c
    ${LIBYAML_DIR}/src/parser.c
    ${LIBYAML_DIR}/src/reader.c
    ${LIBYAML_DIR}/src/scanner.c
    ${LIBYAML_DIR}/src/writer.c
)

# --------------------------------------------------------------------------
# JNI bridge files
# --------------------------------------------------------------------------
set(JNI_BRIDGE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/lwip_jni_bridge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_jni_bridge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/packet_jni_bridge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/geoip_jni_bridge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/vless_jni_bridge.c
    ${CMAKE_CURRENT_SOURCE_DIR}/yaml_jni_bridge.c
)

# --------------------------------------------------------------------------
# Build single shared library
# --------------------------------------------------------------------------
add_library(anywhere_native SHARED
    ${LWIP_SOURCES}
    ${BLAKE3_SOURCES}
    ${CRYPTO_SOURCES}
    ${PACKET_SOURCES}
    ${GEOIP_SOURCES}
    ${VLESS_SOURCES}
    ${LIBYAML_SOURCES}
    ${JNI_BRIDGE_SOURCES}
)

# --------------------------------------------------------------------------
# Include paths
# --------------------------------------------------------------------------
target_include_directories(anywhere_native PRIVATE
    ${LWIP_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto
    ${CMAKE_CURRENT_SOURCE_DIR}/packet
    ${CMAKE_CURRENT_SOURCE_DIR}/geoip
    ${CMAKE_CURRENT_SOURCE_DIR}/vless
    ${LIBYAML_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/compat
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# --------------------------------------------------------------------------
# libyaml needs YAML_DECLARE_STATIC and HAVE_CONFIG_H
# --------------------------------------------------------------------------
target_compile_definitions(anywhere_native PRIVATE
    YAML_DECLARE_STATIC
    HAVE_CONFIG_H
)

# --------------------------------------------------------------------------
# Link libraries
# --------------------------------------------------------------------------
target_link_libraries(anywhere_native
    log
)

# --------------------------------------------------------------------------
# Compiler flags
# --------------------------------------------------------------------------
target_compile_options(anywhere_native PRIVATE
    -Wall
    -Wno-unused-variable
    -Wno-unused-function
    -O2
)
