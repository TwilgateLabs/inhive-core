# Changelog

All notable changes to `inhive-core` (Go DLL/AAR/iOS framework) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases are tagged in git; entries below are grouped by date of major changes
(this codebase is rebuilt-and-vendored per `inhive-app` release rather than
shipped standalone).

## [Unreleased]

(no pending changes — next significant work tracked in `inhive-memory/audit_2026_05_19/02_architectural_assessment.md`)

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
