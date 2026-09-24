# InHive core — architecture (HOW / WHERE)

Go library (Windows DLL, Android AAR, iOS/macOS xcframework) built on a vendored
fork of sing-box. This file says *where things are* and *how to add one more
RPC or protocol*. The *why* lives in memory (`feedback_arch_*`,
`project_grpc_dll.md`, `feedback_build_core_pipeline.md`), in `upstream.toml`
(every deliberate divergence from upstream, with the verified tag/commit), and
in `../app/docs/foundation/2026-09-19-audit-and-program.md` (§3.4, §4, §5.5).
Machine-checked rules live in `hygiene/` — they win over this text.

Line numbers are as of 2026-09-23; confirm with `grep -n` before relying on one.

## 1. Layout and dependency direction

```
core/
  v2/hcore/            gRPC service `Core` + lifecycle: Start/Stop, UrlTest*, per-server ping
                       (url_test_config.go + probe_helpers.go), log stream, speed test. Files around a
                       process-wide `static` (static_data.go). grpc_server.go: Setup (:41),
                       StartGrpcServerByMode (:175), RegisterCoreServer (:247).
  v2/config/           sing-box config builder from InhiveOptions: builder_*.go, outbound.go
                       (patchOutbound :108, patchEndpoint :98), parser.go (patchConfigOptions :229), warp.go
                       InhiveOptions itself is a hand-written Go struct (inhive_option.go:14), not generated
                       from a .proto — there is exactly one definition of it.
  v2/hcommon/          common.proto (Empty/Response), shared helpers
  v2/db/, v2/hutils/
  xray2sing/           separate Go module: share links / subscription text → sing-box options
                       (ray2sing/convert.go registries, ray2sing_test/ corpus)
  sing-box/            vendored sing-box fork (upstream.toml entry `sing-box`, replace/* forks below it)
  platform/            gomobile (mobile/) and desktop (DLL) entry points over hcore
                       (the core CLI `cmd/` + `cmd/bydll` was deleted 2026-09-23 — there is no CLI)
  hygiene/             fitness tests (Go), read the source tree only
  scripts/             build wrappers (build-dll-windows.ps1, verify-aar-abi.ps1, check-upstream-drift.py…)
  Makefile             BASE_TAGS (:24) — the single source of truth for build tags; protos target (:91)
  upstream.toml        registry of vendored trees: path, upstream, tag, commit, divergences
```

Dependency direction (arrows = may import):

```
platform/        →  v2/hcore  →  v2/config  →  v2/hcommon, v2/db
                                    ↓
                                 xray2sing (module, via go.mod replace)
                                    ↓
                                 sing-box fork (+ replace/* forks)  ← nothing above imports upstream internals
                                                                       except through option.* types
```

* `hcore` never builds config JSON itself — it calls `config`.
* `config` never opens sockets or starts boxes — it returns `option.Options`.
* `xray2sing` knows nothing about InHive settings; it parses links into plain sing-box options.
* Patches to `sing-box/` are tracked as divergences in `upstream.toml`; a patch without an entry is drift.

## 2. Registration points

| Kind | Where (file:line) |
|---|---|
| RPC surface | `v2/hcore/hcore_service.proto:9` `service Core` (+ request/response messages in `hcore.proto`) |
| RPC implementation | `func (s *CoreService) <Rpc>` — one method per RPC, grouped by file: `commands.go` (GetSystemInfo :138, SelectOutbound :145, AddOutbound :195, UrlTest :363, SwitchMode :453…), `start.go:23`, `stop.go:12`, `setup.go:28`, `url_test_config.go:47`, `speedtest.go:40`, `logproto.go:33`, `coreinfo.go:28`, `bootstrap_fetch.go:42`, `buildconfighelper.go:79/:128`, `warp.go:11`, `pause.go:54` |
| RPC codegen (Go) | protoc v34.1 (`libprotoc 34.1`, header says `v7.34.1`) + protoc-gen-go v1.36.11 + protoc-gen-go-grpc v1.6.1, from `core/`: `protoc --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative --go_out=./ --go-grpc_out=./ v2/hcore/hcore.proto v2/hcore/hcore_service.proto`. `make protos` (`Makefile:91`) now runs this same codegen for all `v2/*.proto` (Go side only — Dart still has no script, see below) |
| RPC codegen (Dart) | `../app/lib/generated/proto/core_generated/generated/` — protoc_plugin 22.4.0 (`dart pub global activate protoc_plugin`): `protoc --plugin=protoc-gen-dart=<pub-cache>/bin/protoc-gen-dart.bat --dart_out=grpc:<tmp> v2/hcommon/common.proto v2/hcore/hcore.proto v2/hcore/hcore_service.proto`, then `dart format <tmp>` **outside** `app/` (default 80 columns — the checked-in hcore files are formatted that way, not with the app's 120) and copy `v2/hcore/*` over. Verified byte-identical to the checked-in files on 2026-09-23 |
| RPC consumer | `../app/lib/core/bridge.dart` (gRPC channel 127.0.0.1:18078, `bridge.dart:154`) |
| Share-link parser | `xray2sing/ray2sing/convert.go:19` `configTypes` (single outbound), `:65` `endpointParsers` (WireGuard-family endpoints), `:78` `pairParsers` (one link → main + helper outbound) |
| Per-protocol config patch | `v2/config/outbound.go:108` `patchOutbound` (called from `builder_outbound.go:28`), `outbound.go:98` `patchEndpoint` (`builder_outbound.go:79/:112`) |
| Ping probe target | `v2/hcore/url_test_config.go:212` `probeTag` (first non-group outbound / first endpoint) |
| Build tags | `Makefile:23` `BASE_TAGS`, `:44` `IOS_ADD_TAGS`, `:48` `WINDOWS_ADD_TAGS`. Scripts and CI read them with a regex (`.github/workflows/build.yml:108`); never copy the list |
| Packages excluded from `go vet` | `.github/workflows/build.yml:136` (core) and `:149` (sing-box) `EXCL` — with an assert that nothing else fails |
| Vendored versions | `upstream.toml` (`sing-box` = v1.13.21 @ 628cb31f, verified 2026-09-14); check with `python3 scripts/check-upstream-drift.py` **before** any diff against upstream |

## 3. How to add

### 3.1 An RPC

Today:

1. Add the `rpc` line to `hcore_service.proto` (`:9`) and its messages to `hcore.proto`.
2. `make protos` (Go). Regenerate the Dart side into `../app/lib/generated/proto/core_generated/`
   (target: `scripts/gen-proto.{sh,ps1}` with pinned protoc versions, generating both sides — not there yet).
3. Implement `func (s *CoreService) Foo(ctx, in) (resp, err)` in the hcore file that owns the domain
   (or a new small file `foo.go`; do not grow `commands.go`). Wrap panics like the neighbours
   (`recovery_interceptor.go`).
4. Call it from `../app/lib/core/bridge.dart` with a deadline (target: `core/grpc/core_rpc.dart` deadline table).
5. Test: unit test next to the file (`*_test.go`, tags from `Makefile` — `go test` without tags is meaningless
   here), plus the app-side consumer test.

Do not touch: `static_data.go`, `grpc_server.go` (registration is generated), build scripts, `bridge.dart`
beyond the one new method.

Planned gate: `hygiene/rpc_surface_test` — an RPC with no consumer in `../app/lib` and no
`// RESERVED(<date>, <who>): <why>` marker in the proto is red. `SwitchMode` / `ModeStateListener` carry
that marker since 2026-09-23 (see §5); every other RPC in `hcore_service.proto` has a caller in the app.

### 3.2 A protocol

1. Parser: `xray2sing/ray2sing/<proto>.go` + registration in `convert.go` (`configTypes` `:19`, or
   `endpointParsers` `:65` for endpoint-shaped protocols, or `pairParsers` `:78` when one link expands to
   two outbounds). Test in `ray2sing_test/` and a row in `compat_corpus_test.go` (URI → expected JSON).
2. Config patch, if the protocol needs InHive-specific tweaks: a per-protocol hook reached from
   `patchOutbound` (`v2/config/outbound.go:108`; target: a `map[type]patchFn` table instead of an if-chain).
3. Probe: confirm `probeTag` (`url_test_config.go:212`) picks the right outbound; add
   `url_test_config_<proto>_test.go` like the awg/mieru/naive ones.
4. Build tag: if the upstream protocol is behind a tag, add it to `BASE_TAGS` in `Makefile:23` **only**.
   `build.yml` and the PowerShell wrappers read it from there.
5. Vendored code: if the protocol comes with a fork or a new `replace`, add the `upstream.toml` entry in the
   same commit (path, upstream, tag, commit, divergences).
6. Client: `ProtocolSpec` + form section + ARB keys in `../app` (see `../app/ARCHITECTURE.md` §3.4), and a
   parity test “Dart parser == core parser” on the corpus.
7. Add the protocol to the list below.

Do not touch: `hcore/*`, `static_data.go`, build scripts, `bridge.dart`.

Protocols registered today (`convert.go`): vmess, vless, trojan (+ `s`-prefixed variants), ss, tuic,
hysteria, hysteria2/hy2, psiphon, dnstt; endpoints: wg/wireguard/awg/warp/`[Interface]`; pairs: utproto
(parked, see §5).

### 3.3 A setting that reaches the core

Field in the `InhiveOptions` struct (`v2/config/inhive_option.go:14`, hand-written — no codegen) → read it
in the `v2/config/builder_*.go` that owns the section → mirror on the app side (`SettingsState` + fingerprint domain, `../app/ARCHITECTURE.md`
§3.2). Test: builder unit test on the produced `option.Options`.

## 4. Fitness tests and gates

* `hygiene/platform_gate_ratchet_test.go` — every `runtime.GOOS` / `C.IsIos` style gate carries a
  “why these OSes” comment; baseline only goes down. Twin of the app's test.
* `hygiene/xray2sing_cli_deps.go` (build tag `tools`, never compiled) — keeps `spf13/cobra` in core's
  `go.mod`: `xray2sing/cmd` needs it and is vetted from `core/`, and after the core CLI was deleted
  `go mod tidy` (`make prepare`) would drop it. Delete together with `xray2sing/cmd`.
* Planned (`hygiene/`): `rpc_surface_test`, `file_size_ratchet` (commands 541, url_test_config 240…),
  `build_tags_single_source` (a second tag list in ps1/CI is red), `no_root_build_scripts`
  (the 8 untracked `build-aar*.ps1` copies at the root were deleted 2026-09-20; only the canonical
  `build-aar6.ps1` is left, and it still belongs in `scripts/`), unit tests for `v2/db`.
* `scripts/check-upstream-drift.py` — resolves every `upstream.toml` entry on the network and checks the
  recorded tag still points at the recorded commit. Weekly non-blocking run: workflow `upstream-drift`.
* `go vet` per module with `BASE_TAGS` (command in `../CLAUDE.md` “Build & Test Hygiene”); CI does the same
  for `core`, `sing-box` and `xray2sing` with an assert on unlisted failures.
* Build wrappers are the only sanctioned build path (`scripts/build-dll-windows.ps1`, `make android`,
  `make ios`): they sync `libcronet`, stamp the version, enforce 3 ABIs. Raw `go build` / `gomobile bind` is
  not a build.

## 5. Reserved (parked, do not delete)

From the audit §5.5 — keep, mark with `// RESERVED(<date>, <who>): <why>` where a gate would otherwise flag it:

Items marked † carry a `RESERVED(2026-09-23, Nikita)` comment in the code (grep `RESERVED(2026-09-23`).

* † olcrtc / UTProto branches in hcore (`static_data.go` startCancel, `start.go`, `stop.go`,
  `url_test_config.go`, `commands.go`, build tag `with_olcrtc`) — memory
  `project_olcrtc_utproto_disabled_2026_09_06`: “nothing deleted”.
* † `SwitchMode` / `ModeStateListener` (+ `urltest_watcher.go`, `currentMode` / `modeStateObserver`) —
  `project_olcrtc_implementation` “do not touch”; RESERVED marker in `hcore_service.proto` and `commands.go`.
* † DAITA / maybenot: `daita_machines.go`, `initDaita` (`buildconfighelper.go`), `daita-*` options,
  the submodule, `scripts/build_libmaybenot_ios.sh`.
* `bootstrap_fetch.go` on the legacy side instance (`project_ping_audit_2026_07_12`: deliberate).
* iOS scripts and targets: `ios_preflight.sh`, `fix_xcframework_ios.sh`, `verify-native-freshness.sh`,
  `Makefile:185-213` (`ios`, `ios-deploy`), `Info.plist`.
* libcronet / naive pipeline: `Makefile:226-289` (`windows-naive-lib`, `windows-amd64`), `verify-cronet-pin.ps1`, CI naive liveness
  (`build.yml:247-283`).
* `xray2sing` as a whole (out of scope for the cut).
* mTLS branches for `SetupMode` 1/2 in `grpc_server.go:175-269` (`StartGrpcServerByMode`).
* Platform-specific tuning that is not to be unified: Android gvisor, iOS `GOMAXPROCS`/`SetMemoryLimit`,
  `DisablePathMTUDiscovery`; `uploadBudget` / `streamSlots` (do not revive).

## 6. Facts that are often misremembered

* The app connects on **18078**. `17078` was the CLI default (`cmd/`, `hcore/standalone.go`), both
  deleted 2026-09-23; it survives only in old CHANGELOG lines, a comment in `platform/mobile/mobile.go:43`
  and `SECURITY.md:80` (stale). `SetupMode=4` = `GRPC_NORMAL_INSECURE` on loopback; the
  lack of auth on that port is an open question (§11 of the audit), not an oversight to “fix” in passing.
* Vendored sing-box is **v1.13.21** (`upstream.toml`), sing 0.8 line; the 1.14 / sing 0.9 move is a
  separate project (re-fork as a patch series, not a merge).
* Mixed inbound for HTTP/SOCKS is `127.0.0.1:12334`; clash API is `9090`.
