<div align="center">

<div>
    <a href="https://play.google.com/store/apps/details?id=com.argsment.anywhere">
        <img width="100" height="100" alt="Anywhere" src="https://storage.argsment.com/Anywhere-AppIcon-Android.png" />
    </a>
</div>

# Anywhere for Android

**The best native proxy client for Android.**

A native, zero-dependency proxy client built entirely in Kotlin.
No Electron. No WebView. No sing-box wrapper. Pure protocol implementation from the ground up.

<div>
    <a href="https://play.google.com/store/apps/details?id=com.argsment.anywhere">
        <img width="128" src="https://storage.argsment.com/Get%20it%20on%20Google%20Play.png" />
    </a>
</div>

</div>

---

## Why Anywhere?

Most Android proxy clients wrap sing-box or Xray-core in a Go/C++ bridge. Anywhere implements the protocol, transport, and routing layers directly in Kotlin, and calls into a small set of vendored C libraries (lwIP, ngtcp2, BLAKE3, libyaml) through JNI for the parts that benefit from native code. The result is a smaller binary, lower memory usage, and no Go runtime overhead.

## Features

### Protocols & Security

- **VLESS** with full Vision (XTLS-RPRX-Vision) flow control and adaptive padding
- **Hysteria2** over QUIC with Brutal congestion control
- **Trojan** over TLS with UDP-over-TCP relay
- **Shadowsocks** (AEAD and Shadowsocks 2022)
- **SOCKS5** with optional authentication
- **Naive Proxy** (HTTP/1.1, HTTP/2, HTTP/3) with padding negotiation
- **Reality** with X25519 key exchange and TLS 1.3 fingerprint spoofing
- **TLS** with SNI, ALPN, custom trusted certificates, and optional insecure mode
- **Transports:** TCP, WebSocket (with early data), HTTP Upgrade, XHTTP (stream-one, stream-up, and packet-up over HTTP/1.1 and HTTP/2)
- **Mux** multiplexing with **XUDP** (GlobalID-based, BLAKE3 keyed hashing)
- **Fingerprints:** Chrome, Firefox, Safari, iOS, Edge

### App

- **ASR™ Smart Routing** — reduce latency while routing through proxy on demand
- **One-tap connect** with animated status UI and real-time traffic stats
- **Proxy chains** — cascade traffic through multiple outbounds
- **Subscription import** with auto-detection, auto-refresh, and profile metadata
- **Deep link support** for quick proxy/subscription import (see [Deep Links](#deep-links))
- **QR code scanner** for instant config import
- **Latency testing** per-configuration
- **Custom routing rule sets** with domain/IP/GeoIP matching (MaxMind GeoLite2)
- **Country bypass** — exclude traffic by destination country
- **Built-in ad blocking** rule set
- **Encrypted DNS** (DNS-over-HTTPS, DNS-over-TLS) with auto-upgrade
- **IPv6** support with configurable behavior
- **Always On** / on-demand VPN
- **Trusted certificate** management for private CAs
- **Xray-core compatible** — works with standard V2Ray/Xray server deployments

### Architecture

- **Minimal dependencies** — Android frameworks, vendored C libraries (lwIP, ngtcp2, blake3, libyaml)
- **Native VPN Service** — system-wide VPN via `VpnService` with a userspace TCP/IP stack
- **Fake-IP DNS** — transparent domain-based routing for all apps
- **Vendored native code** — lwIP (TCP/IP), ngtcp2 (QUIC for Hysteria and NaiveProxy H3), BLAKE3 (keyed hashing), libyaml (Clash parsing); bundled into a single `libanywhere_native.so`
- **Jetpack Compose** UI with Material 3
- **arm64-v8a** native binaries

## Getting Started

### Build from Source

```bash
git clone https://github.com/NodePassProject/Anywhere-Android.git
cd Anywhere-Android
```

Open the project in Android Studio, sync Gradle, select the `app` configuration, choose your device, and hit Run. A prebuilt APK is available at the download link above.

## License

Anywhere is licensed under the [GNU General Public License v3.0](LICENSE).

---

If you find Anywhere useful, consider starring the repo. It helps others discover it.
