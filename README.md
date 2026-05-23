<p align="center">
  <img src="https://raw.githubusercontent.com/TwilgateLabs/inhive-core/main/assets/logo.svg" alt="InHive Logo" width="128">
</p>

<h1 align="center">InHive Core</h1>

<p align="center">
  <strong>The Ultimate Universal Proxy Platform</strong><br>
  A powerful, high-performance core for the InHive ecosystem, supporting all major protocols and platforms.
</p>

<p align="center">
  <a href="https://inhive.ru"><img src="https://img.shields.io/badge/Website-inhive.ru-blue?style=flat-square" alt="Website"></a>
  <a href="https://t.me/inhive_bot"><img src="https://img.shields.io/badge/Telegram-Join-blue?style=flat-square&logo=telegram" alt="Telegram"></a>
  <img src="https://img.shields.io/github/license/TwilgateLabs/inhive-core?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/v/release/TwilgateLabs/inhive-core?style=flat-square" alt="Version">
</p>

---

## Quick Setup

Install `inhive-core` on any Linux platform (Ubuntu, Debian, CentOS, OpenWrt, and more) with a single command:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/TwilgateLabs/inhive-core/main/installer.sh)
```

> **Note:** This script automatically detects your OS and architecture, installs the appropriate binary, and configures the service manager (Systemd or Procd).

---

## Key Features

- **Multi-Protocol Support**: VLESS (Reality / XHTTP / XTLS-Vision), VMess, Trojan, Shadowsocks, ShadowTLS, WireGuard, AmneziaWG, Hysteria2, TUIC, SOCKS, NaiveProxy, Mieru, DNSTT, Tor, and more.
- **UTProto (FakeTLS)**: Custom MTProto-derived transport that mimics TLS handshake, invisible to DPI — developed in-house.
- **Cross-Platform**: Powering InHive on Android, macOS, Linux, Windows, and iOS.
- **High Performance**: Optimized core built on top of `sing-box` for maximum speed and stability.
- **Router Ready**: Native support for OpenWrt and other router platforms.

---

## Installation Methods

### Docker
```bash
docker pull ghcr.io/TwilgateLabs/inhive-core:latest

# Or using Docker Compose
git clone https://github.com/TwilgateLabs/inhive-core
cd inhive-core/platform/docker
docker-compose up -d
```

### OpenWrt
Install via the universal installer script — it auto-detects OpenWrt and configures procd service.

---

## Roadmap

### Done
- [x] Fork and rebrand from Hiddify Core
- [x] CI/CD pipeline with GitHub Actions
- [x] Full code audit and dead code cleanup (~5400 lines of dead code removed)
- [x] Critical bug fixes (tunnel service, config builder, service manager)
- [x] Dependency updates (Go 1.26, grpc v1.80, sing v0.8.4, sing-box v1.13.0)
- [x] NaiveProxy support (Chromium TLS stack)
- [x] naive+https:// and naive+quic:// scheme variants support
- [x] Hysteria2 / TUIC support (high-performance UDP-based protocols)
- [x] AmneziaWG (AWG) — WireGuard variant with junk packets / fragmentation
- [x] Mieru / DNSTT outbound support
- [x] Go 1.26 TLS compatibility (removed psiphon, fixed WireGuard deprecated warnings)
- [x] UTProto outbound — FakeTLS transport (MTProto-derived) — developed in-house
- [x] UTProto URI scheme: `utproto://SECRET@HOST:PORT?tls_domain=DOMAIN&vless_uuid=UUID&vless_port=PORT#Name`
- [x] Android build target — gomobile AAR with 3 ABIs (arm64-v8a + armeabi-v7a + x86_64)
- [x] iOS build target — XCFramework with arm64-device + arm64-simulator slices

### Planned
- [ ] macOS build target — XCFramework with macOS slice for native Flutter macOS apps
- [ ] Linux build target — shared library for Flutter desktop integration

> **Note:** Client-app roadmap (UI, TUN integration, Split tunnel, platform clients) is tracked in [twilgate/inhive-app](https://github.com/twilgate/inhive-app). This repository covers only the Go core / proxy engine.

---

## Building

### Desktop (C shared library)
```bash
make windows-amd64
make linux-amd64
make macos
```

### Mobile (gomobile)
```bash
make android
make ios
```

---

## Team

| Role | Who |
|------|-----|
| **Idea & Product** | [@twilgate](https://github.com/twilgate) |
| **Core Development** | [Claude](https://claude.ai) (AI-assisted engineering) |

---

## License

[GPL-3.0-or-later](LICENSE.md) — based on [Hiddify](https://github.com/hiddify/hiddify-core) open-source project.
