# InHive core — architecture (HOW / WHERE)

Go library (Windows DLL, Android AAR, iOS/macOS xcframework) built on a vendored
fork of sing-box. This file says *where things are* and *how to add one more
RPC or protocol*. The *why* lives in memory (`feedback_arch_*`,
`project_grpc_dll.md`, `feedback_build_core_pipeline.md`), in `upstream.toml`
(every deliberate divergence from upstream, with the verified tag/commit), and
in `../app/docs/foundation/2026-09-19-audit-and-program.md` (§3.4, §4, §5.5).
Machine-checked rules live in `hygiene/` — they win over this text.

Line numbers are as of 2026-09-19; confirm with `grep -n` before relying on one.

## 1. Layout and dependency direction

```
core/
  v2/hcore/            gRPC service `Core` + lifecycle: Start/Stop/Restart, UrlTest*, warm probe,
                       log stream, system proxy, speed test. 40 files around a process-wide `static`
                       (static_data.go). grpc_server.go: Setup (:41), StartGrpcServerByMode (:214),
                       RegisterCoreServer (:178 / :286).
  v2/config/           sing-box config builder from InhiveOptions: builder_*.go, outbound.go
                       (patchOutbound :108, patchEndpoint :98), parser.go (patchConfigOptions :229), warp.go
  v2/inhiveoptions/    DEAD (audit 2026-09-19 §5.1, confirmed by two refuters): duplicate of config.InhiveOptions
                       (v2/config/inhive_option.go:14 is the live one); removed in phase 3 — do not build on it
  v2/profile/          DEAD (audit 2026-09-19 §5.1): 0 importers, RegisterProfileServiceServer never called;
                       removed in phase 3 together with v2/config/core*.pb.go + config_server.go
  v2/hcommon/          common.proto (Empty/Response), shared helpers
  v2/db/, v2/hutils/, v2/service_manager/
  xray2sing/           separate Go module: share links / subscription text → sing-box options
                       (ray2sing/convert.go registries, ray2sing_test/ corpus)
  sing-box/            vendored sing-box fork (upstream.toml entry `sing-box`, replace/* forks below it)
  platform/            gomobile (mobile/) and desktop (DLL) entry points over hcore
  cmd/                 CLI (cmd_inhive_run.go: default listen 127.0.0.1:17078 — the app does NOT use this)
  hygiene/             fitness tests (Go), read the source tree only
  scripts/             build wrappers (build-dll-windows.ps1, verify-aar-abi.ps1, check-upstream-drift.py…)
  Makefile             BASE_TAGS (:24) — the single source of truth for build tags; protos target (:86)
  upstream.toml        registry of vendored trees: path, upstream, tag, commit, divergences
```

Dependency direction (arrows = may import):

```
platform/, cmd/  →  v2/hcore  →  v2/config  →  v2/inhiveoptions, v2/hcommon, v2/profile
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
| RPC implementation | `func (s *CoreService) <Rpc>` — one method per RPC, grouped by file: `commands.go` (SelectOutbound :199, AddOutbound :249, UrlTest :417, SwitchMode :503…), `start.go:24`, `stop.go:12`, `restart.go:13`, `setup.go:24`, `url_test_config.go:47`, `warm_probe.go:297`, `speedtest.go:40`, `logproto.go:33`, `bootstrap_fetch.go:40`, `buildconfighelper.go:86/:135`, `warp.go:11`, `pause.go:54`, `proxy_info.go:182` |
| RPC codegen (Go) | `Makefile:86` target `protos` (protoc-gen-go + grpc; `.pb.go` next to the `.proto`) |
| RPC codegen (Dart) | `../app/lib/generated/proto/core_generated/` (protoc dart plugin, invoked by hand today) |
| RPC consumer | `../app/lib/core/bridge.dart` (gRPC channel 127.0.0.1:18078, `bridge.dart:150`) |
| Share-link parser | `xray2sing/ray2sing/convert.go:19` `configTypes` (single outbound), `:65` `endpointParsers` (WireGuard-family endpoints), `:78` `pairParsers` (one link → main + helper outbound) |
| Per-protocol config patch | `v2/config/outbound.go:108` `patchOutbound` (called from `builder_outbound.go:28`), `outbound.go:98` `patchEndpoint` (`builder_outbound.go:79/:112`) |
| Ping probe target | `v2/hcore/url_test_config.go:212` `probeTag` (first non-group outbound / first endpoint) |
| Build tags | `Makefile:24` `BASE_TAGS`, `:45` `IOS_ADD_TAGS`, `:50` `WINDOWS_ADD_TAGS`. Scripts and CI read them with a regex (`.github/workflows/build.yml:108`); never copy the list |
| Packages excluded from `go vet` | `.github/workflows/build.yml:137` (core) and `:150` (sing-box) `EXCL` — with an assert that nothing else fails |
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
`// RESERVED(<date>, <who>): <why>` marker in the proto is red. `SwitchMode` / `ModeStateListener` are the
first RESERVED candidates (see §5).

### 3.2 A protocol

1. Parser: `xray2sing/ray2sing/<proto>.go` + registration in `convert.go` (`configTypes` `:19`, or
   `endpointParsers` `:65` for endpoint-shaped protocols, or `pairParsers` `:78` when one link expands to
   two outbounds). Test in `ray2sing_test/` and a row in `compat_corpus_test.go` (URI → expected JSON).
2. Config patch, if the protocol needs InHive-specific tweaks: a per-protocol hook reached from
   `patchOutbound` (`v2/config/outbound.go:108`; target: a `map[type]patchFn` table instead of an if-chain).
3. Probe: confirm `probeTag` (`url_test_config.go:212`) picks the right outbound; add
   `url_test_config_<proto>_test.go` like the awg/mieru/naive ones.
4. Build tag: if the upstream protocol is behind a tag, add it to `BASE_TAGS` in `Makefile:24` **only**.
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

Field in `v2/inhiveoptions/inhive_options.proto` → regenerate → read it in the `v2/config/builder_*.go`
that owns the section → mirror on the app side (`SettingsState` + fingerprint domain, `../app/ARCHITECTURE.md`
§3.2). Test: builder unit test on the produced `option.Options`.

## 4. Fitness tests and gates

* `hygiene/platform_gate_ratchet_test.go` — every `runtime.GOOS` / `C.IsIos` style gate carries a
  “why these OSes” comment; baseline only goes down. Twin of the app's test.
* Planned (`hygiene/`): `rpc_surface_test`, `file_size_ratchet` (warm_probe 869, commands 591…),
  `build_tags_single_source` (a second tag list in ps1/CI is red), `no_root_build_scripts`
  (`build-aar*.ps1` ×8 at the root are the anti-pattern), unit tests for `v2/db`.
* `scripts/check-upstream-drift.py` — resolves every `upstream.toml` entry on the network and checks the
  recorded tag still points at the recorded commit. Weekly non-blocking run: workflow `upstream-drift`.
* `go vet` per module with `BASE_TAGS` (command in `../CLAUDE.md` “Build & Test Hygiene”); CI does the same
  for `core`, `sing-box` and `xray2sing` with an assert on unlisted failures.
* Build wrappers are the only sanctioned build path (`scripts/build-dll-windows.ps1`, `make android`,
  `make ios`): they sync `libcronet`, stamp the version, enforce 3 ABIs. Raw `go build` / `gomobile bind` is
  not a build.

## 5. Reserved (parked, do not delete)

From the audit §5.5 — keep, mark with `// RESERVED(<date>, <who>): <why>` where a gate would otherwise flag it:

* olcrtc / UTProto branches in hcore (`static_data.go:75-82` startCancel, `start.go`, `stop.go`,
  `url_test_config.go`, `warm_probe.go`, `commands.go`, build tag `with_olcrtc`) — memory
  `project_olcrtc_utproto_disabled_2026_09_06`: “nothing deleted”.
* `SwitchMode` / `ModeStateListener` (+ `urltest_watcher.go`, `currentMode` / `modeStateObserver`) —
  `project_olcrtc_implementation` “do not touch”; needs the RESERVED marker in the proto.
* DAITA / maybenot: `daita_machines.go`, `initDaita` (`buildconfighelper.go:61-83`), `daita-*` options,
  the submodule, `scripts/build_libmaybenot_ios.sh`.
* `bootstrap_fetch.go` on the legacy side instance (`project_ping_audit_2026_07_12`: deliberate).
* iOS scripts and targets: `ios_preflight.sh`, `fix_xcframework_ios.sh`, `verify-native-freshness.sh`,
  `Makefile:186-218`, `Info.plist`.
* libcronet / naive pipeline: `Makefile:250-290`, `verify-cronet-pin.ps1`, CI naive liveness
  (`build.yml:249-284`).
* `xray2sing` as a whole (out of scope for the cut).
* mTLS branches for `SetupMode` 1/2 in `grpc_server.go:202-290`.
* Platform-specific tuning that is not to be unified: Android gvisor, iOS `GOMAXPROCS`/`SetMemoryLimit`,
  `DisablePathMTUDiscovery`; `uploadBudget` / `streamSlots` (do not revive).

## 6. Facts that are often misremembered

* The app connects on **18078**; `17078` appears only in `cmd/` and `hcore/standalone.go:195` as the CLI
  default (and in old CHANGELOG/SECURITY lines). `SetupMode=4` = `GRPC_NORMAL_INSECURE` on loopback; the
  lack of auth on that port is an open question (§11 of the audit), not an oversight to “fix” in passing.
* Vendored sing-box is **v1.13.21** (`upstream.toml`), sing 0.8 line; the 1.14 / sing 0.9 move is a
  separate project (re-fork as a patch series, not a merge).
* Mixed inbound for HTTP/SOCKS is `127.0.0.1:12334`; clash API is `9090`.
