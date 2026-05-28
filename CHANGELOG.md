# Changelog

All notable changes to `inhive-core` (Go DLL/AAR/iOS framework) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases are tagged in git; entries below are grouped by date of major changes
(this codebase is rebuilt-and-vendored per `inhive-app` release rather than
shipped standalone).

## [Unreleased]

### Added

- **olcrtc Phase 1**: stealth tunnel outbound `type: olcrtc` for emergency RU LTE whitelist scenarios (`with_olcrtc` build tag, default-on). Outbound is registered always; stub returns clear error if built without the tag.
- **olcrtc Phase 2 (generic mode switch infra)**: new gRPC `SwitchMode(int32 mode)` RPC + `ModeStateListener` server stream. URLTest health watcher (sliding window 10, threshold 7+ consecutive failures or 70%+ rate, debounce 30s) emits "switch recommended" events. Core only signals state — hard cross-mode switch is the main app's job (NE Provider restart).
- **olcrtc Phase 2.5 (fork + H-1 rewrite + SEC-2/3 hardening)**: Forked `openlibrecommunity/olcrtc` → `TwilgateLabs/inhive-olcrtc` with `internal/client` promoted to `pkg/olcrtc/client` so VPN outbound embedders can access the multiplexing client API. `core/sing-box/protocol/olcrtc/outbound.go` rewritten to use `client.RunWithReady` + local SOCKS5 detour (Pattern A — same approach as naive outbound), fixing H-1 traffic cross-contamination. Schema in `option/olcrtc.go` extended with `ChannelID` (UUID-validated), `KeyHex` (64 hex chars), `Transport`, `SocksAddr/User/Pass`. SEC-2 hard-pins `transport=datachannel` (blocks video transport DoS surface); SEC-3 defaults `dns_server=9.9.9.9:53` (Quad9 — protects telemetry beacon endpoint from DNS poisoning).
- **olcrtc Phase 2.5 Этап 4 (fork hardening)**: Bumped `TwilgateLabs/inhive-olcrtc` to `v0.0.2-inhive` (scrubbed hostile Russian comments in vp8channel; gutted `sendTelemetry()` body to defeat DNS-poisoning side-channel beacon — SEC-3 server-side and SEC-6). Added `replace github.com/zarazaex69/j => github.com/TwilgateLabs/inhive-j-deps v0.0.1-inhive` (force-disabled `InsecureSkipVerify` in XMPP dial paths regardless of caller flag — SEC-5 MITM defense). No outbound code change; same call paths now traverse hardened transports.

### Fixed

- **iOS phantom connected** (2026-05-28): rolled back sing-box submodule to `bb159078` — reverts `2e288c2d feat(olcrtc): make Start() non-blocking`. On iOS NE Provider, non-blocking Start let `sing-box` service init complete before olcrtc client finished its WebRTC handshake — TUN routes applied while DialContext was still waiting on readyCh (up to 30s), iOS app-level DNS/HTTP timeouts (5–10s) fired first, traffic died with status bar VPN ON. Verified fixed on iPhone 14 — real IP exits through NL olcrtc joiner, not selector fallback to LV. Multi-room pool failover (the feature `2e288c2d` enabled) is still broken until a non-race approach lands (e.g. parallel Start with per-outbound timeout that doesn't block service init).
- **gvisor / amneziawg c-shared build break**: `make windows`/`make macos` failed with `bridge_test.go` mixed-package error after Phase 1 `go mod tidy` transitively bumped amneziawg-go v0.2.18 → v1.0.4 (which requires the new gvisor API). Pinned amneziawg-go back to v0.2.18 via `replace` directive and pinned gvisor to v0.0.0-20240503... (last clean version before `bridge_test.go` was added). Full c-shared build now Exit 0 with production tags.

## [2026-05-20]

### Security

- `SECURITY.md` added — coordinated disclosure policy (GitHub Security Advisory primary), Tier 1/2 classification per [ADR-009](https://github.com/twilgate/inhive-memory/blob/main/docs/adr/009-stealth-security-releases.md).
- `.github/dependabot.yml` — Go modules + GitHub Actions weekly auto-update (per [ADR-002 fork sing-box](https://github.com/twilgate/inhive-memory/blob/main/docs/adr/002-fork-sing-box.md) maintenance discipline).
- `actions/checkout` and `actions/setup-go` in `.github/workflows/build.yml` finalized SHA-pinned (per audit 07_dependency_strategy.md P0).

## [2026-05-15] — Go 1.26 + sing-box v0.8.4 stable

### Changed

- **Go toolchain:** 1.25 → 1.26 (per upstream sing-box requirement).
- **sing-box dependency:** `v0.8.0-beta` → `v0.8.4` stable.

## [2026-04-25] — Dehiddification finalized + canonical naming

### Changed

- **Module rename:** `github.com/hiddify/hiddify-core` → `github.com/TwilgateLabs/inhive-core` (gomobile path migration — see `feedback_build_gomobile_path_migration.md`).
- **Repository name:** `inhive-singbox` → `inhive-core` for clarity (it's not just sing-box, it's the full core with gRPC layer + system proxy + custom protocols).

### Removed

- All `hiddify-*` import paths replaced with `TwilgateLabs/*`.

## [2026-04-23] — UTProto Phase 1

### Added

- **UTProto** (Universal Transport Protocol) — native sing-box TCP inbound on port 3444. Previously was a 2-process Xray + Python relay; Phase 1 migrated to single-process sing-box native inbound for naive.
- See `project_utproto_architecture.md` and `project_utproto_naming.md` for design rationale.

## [2026-04-20] — Dehiddification 2026-04-20

### Changed

- **Migrated from `hiddify-next/hiddify-core` fork to canonical `SagerNet/sing-box` vendored** + InHive-specific patches (UTProto, warpobf, InhiveOptions, xray2sing, custom config builder).
- New module path: `github.com/TwilgateLabs/inhive-core`.
- SagerNet rule-sets adopted for routing decisions.

## [2026-02 .. 2026-04] — Reality + NaiveProxy + grpc

### Added

- **Reality (XTLS Vision)** as primary VPN protocol — see [ADR-001](https://github.com/twilgate/inhive-memory/blob/main/docs/adr/001-reality-primary-protocol.md).
- **NaiveProxy outbound** with `with_purego` build flag — required `cronet` frameworks + `fix_xcframework` for iOS (see `feedback_build_ios_cronet_purego.md`).
- **gRPC control plane** (`SetupMode=4`, port 17078) — Flutter `inhive-app` connects via gRPC over loopback. Stateless contract.
- **System proxy injection (Windows)** via Advapi32 + Wininet registry write — auto-attach Windows global proxy.

### Build pipeline

- Windows: `inhive-core.dll` (CGO, build flags include `tfogo_checklinkname0`, `with_purego`).
- Android: `inhive-core.aar` for 3 ABI (arm64, armeabi-v7a, x86_64) — see `feedback_build_core_pipeline.md`.
- iOS: gomobile bindings → framework, with `fix_xcframework` post-processing.

## [Initial]

Fork of `hiddify-core` (`hiddify-next/hiddify-core` upstream). InHive-specific
patches preserved across upstream merges via `git merge` strategy (not rebase
— see `feedback_build_singbox_merge.md`).

Foundation decisions: see [ADR-001 .. ADR-014](https://github.com/twilgate/inhive-memory/tree/main/docs/adr) for architectural rationale.
