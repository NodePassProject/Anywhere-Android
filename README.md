<div align="center">

<div>
    <a href="https://download.argsment.com/Anywhere.apk">
        <img width="100" height="100" alt="Anywhere" src="https://github.com/user-attachments/assets/715e572b-49a0-4c97-b8e6-1b75bcaf7ae7" />
    </a>
</div>

# Anywhere for Android

**The best VLESS client for Android.**

A native, zero-dependency VLESS client built entirely in Kotlin and C.
No Electron. No WebView. No sing-box wrapper. Pure protocol implementation from the ground up.

<div>
    <a href="https://download.argsment.com/Anywhere.apk">
        <img width="128" src="https://github.com/user-attachments/assets/6d09fd9a-3f0c-4a29-87ab-01c23b0b2b35" />
    </a>
</div>

</div>

---

## Why Anywhere?

Most Android proxy clients wrap sing-box or Xray-core in a Go/C++ bridge. Anywhere takes a different approach — every protocol, every transport, and the entire VPN stack is implemented natively in Kotlin and C. The result is a smaller binary, lower memory usage, tighter system integration, and no bridging overhead.

## Features

### Protocols & Security

- **VLESS** with full Vision (XTLS-RPRX-Vision) flow control and adaptive padding
- **Reality** with X25519 key exchange, TLS 1.3 fingerprint spoofing (Chrome, Firefox, Safari, Edge, iOS)
- **TLS** with SNI, ALPN, and optional insecure mode
- **Transports:** TCP, WebSocket (with early data), HTTP Upgrade, XHTTP (stream-one & packet-up)
- **Mux** multiplexing with **XUDP** (GlobalID-based, BLAKE3 keyed hashing)

### App

- **One-tap connect** with animated status UI and real-time traffic stats
- **QR code scanner** for instant config import
- **Subscription import** with auto-detection and profile metadata
- **Manual editor** for full control over every parameter
- **Latency testing** with color-coded indicators and batch "Test All"
- **Domain routing rules** with exact, suffix, and keyword matching — built-in rule sets for Telegram, Netflix, YouTube, Disney+, TikTok, ChatGPT, Claude
- **Country bypass** — GeoIP-based split routing (CN, RU, IR, TM, MM, BY, SA, AE, VN, CU)
- **DNS over HTTPS** toggle
- **IPv6** support
- **Always On VPN**
- **Xray-core compatible** — works with standard V2Ray/Xray server deployments

### Architecture

- **Zero third-party dependencies** — Android frameworks + vendored C libraries (lwIP, BLAKE3)
- **Native VPN Service** — system-wide VPN via `VpnService` with userspace TCP/IP stack (lwIP)
- **Fake-IP DNS** — transparent domain-based routing for all apps
- **Jetpack Compose** UI with Material 3 and dynamic theming
- **arm64-v8a** native binaries

## Getting Started

### Requirements

- Android 15+ (API 36)
- Android Studio with NDK and CMake

### Build from Source

```bash
git clone https://github.com/NodePassProject/Anywhere-Android.git
cd Anywhere-Android
```

Open the project in Android Studio, sync Gradle, select the `app` configuration, choose your device, and hit Run.

## License

Anywhere is licensed under the [GNU General Public License v3.0](LICENSE).

---

If you find Anywhere useful, consider starring the repo. It helps others discover it.
