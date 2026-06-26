# Changelog

All notable changes to `inhive-core` (Go DLL/AAR/iOS framework) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases are tagged in git; entries below are grouped by date of major changes
(this codebase is rebuilt-and-vendored per `inhive-app` release rather than
shipped standalone).

## [Unreleased]

### Added (2026-06-26 — on-device memory diagnostics)

- **Memory sampler in the log.** The core now prints a compact memory line every 10 seconds — `mem: phys_footprint=… heap=… sys=… goroutines=… gc=…` — so you can watch the core's memory on the phone straight from the in-app logs (no Xcode needed). On iOS it includes `phys_footprint`, the exact metric the system uses to decide whether to kill the tunnel. Read-only; runs on every platform and stops cleanly when the VPN stops.

### Changed (2026-06-26 — iOS memory footprint)

- **Fewer OS threads on iOS.** The core now pins itself to a single scheduler thread on iOS only. Each extra thread costs memory the tunnel can't spare under the iOS budget, and a VPN proxy is I/O-bound so the lost parallelism doesn't matter. Windows and Android are unchanged.
- **The core log file no longer grows without bound.** `box.log` used to append forever (it had reached 59 MB). It's now capped: when it passes ~5 MB it's rotated to a single backup at startup. No new dependency was added.
- **Less log spam on broken DNS packets.** The "process DNS packet" error used to be logged once per bad packet (thousands of times during an outage), which itself burned memory. It's now rate-limited to once a second with a "(+N suppressed)" tail.

### Fixed (2026-06-26 — iOS freeze hardening)

- **iOS app no longer freezes after a long server outage.** After the server was unreachable for hours, the core could lock up and stop reconnecting even once the server came back (you'd see a connected-looking screen that didn't respond). Four changes address the root causes:
  - **Cap on DNS request flooding.** When the upstream DNS was down, the core spawned an unbounded worker per DNS packet; these piled up faster than they drained and slowly exhausted the iOS memory budget. There's now a generous concurrency cap — under a real flood, excess packets are dropped (with a once-a-second log line) instead of accumulating.
  - **Stuck server connection now gets recycled.** A connection left in a failed state after "connection refused" used to be reused forever, so reconnect never happened. It's now invalidated after a failed attempt so the next try opens a fresh one — without disturbing the built-in reconnect/backoff for healthy connections.
  - **Lower memory ceiling on iOS.** The previous memory target was set high enough that real usage drifted past the system's hard limit, putting the runtime into a permanent garbage-collection stall instead of a clean restart. Lowered the target and relaxed the collector to leave proper headroom.
  - **Memory-pressure safety net enabled.** On iOS, the core now reacts to system memory-pressure warnings by shedding connections and releasing memory before the OS would kill the tunnel.

### Added (2026-06-24 — parser consolidation)

- **`parse` desktop C-export** (`platform/desktop/custom.go`): the FFI sibling of `MobileParse` — pure `Ray2Singbox` over `libbox.BaseContext`, no `setup()`/running engine. Lets the Windows/macOS/Linux Flutter app parse subscriptions through the canonical Go parser via the loaded DLL/dylib (no gRPC, no disk side-effects), bringing the desktop on par with iOS/Android. On error returns `{"__parse_error__":"…"}` (C ABI has no exceptions). Result must be freed via `freeString`.
- **`MobileParse` gomobile export** (`platform/mobile/mobile.go`): pure function that converts subscription content → sing-box config JSON via the canonical `xray2sing.Ray2Singbox`. No `MobileSetup`/running engine required (uses `libbox.BaseContext`). This lets the Flutter app call the **single source-of-truth** Go parser in-process instead of its lossy Dart reimplementation (`singbox_config_builder`), so the two parsers can no longer drift — the root cause of the `truesight` xhttp-obfs gap surviving even after the protocol-parity wave landed in Go. Wired on iOS (Swift `parseConfig` channel → `MainAppCore.parse`) and Android (`VpnMethodHandler.parseConfig` → `Mobile.parse`); desktop uses the `parse` C-export above. All three platforms now parse through the core, and the Dart standard-protocol reimplementation has been deleted app-side.

### Added (2026-06-23 — protocol-parity wave)

- **XHTTP/SplitHTTP CDN-bypass obfuscation** (the `truesight`-class bug): upstream Xray's xhttp obfs knobs were unported, so a config that dials in Happ/Xray (`uplinkHTTPMethod=GET`, `xPaddingMethod=tokenish`, `seqKey`/`sessionKey` placement, `queryInHeader`) silently degraded against a server that requires them. Added the full **client-side** obfs to `transport/v2rayxhttp` + `option/v2ray_transport.go`: `uplinkHTTPMethod`, `seqKey/seqPlacement`, `sessionID*` (+ `sessionKey`/`sessionPlacement` aliases), `xPaddingMethod` (`repeat-x`/`tokenish`), `xPaddingObfsMode/Key/Header/Placement` (incl. `queryInHeader`). All opt-in — the default-unset path is **byte-identical** to before (`x_padding`=repeat-X in query, path-based session/seq, POST uplink). Server-side not implemented (we only need to speak their protocol). Caveat: `tokenish` padding is a flat base62 token, not yet iteratively HPACK/QPACK-Huffman-length-matched.
- **JSON-container subscription ingest**: Xray/Happ `{"outbounds":[…]}`, SIP008 `{"servers":[…]}`, and bare JSON arrays now import instead of returning "No outbounds found". Sniffs the first non-space byte, rebuilds each entry to a `vless://`/`vmess://`/`trojan://`/`ss://` URI and reuses the existing per-protocol parsers. `dns`/`routing` blocks are **intentionally dropped** (InHive owns DNS/routing — avoids a subscription-driven DNS leak). New `xray2sing/ray2sing/json_ingest.go`.
- **anytls:// and shadowtls:// share-link schemes** — the dialers were already registered; only the parser bridge was missing. Plus **socks4/socks5/socks4a/socks5h** scheme aliases (version derived from scheme).
- **Transport parity**: gRPC `authority` + `user_agent` + idle/health/permit timeouts; WebSocket `heartbeatPeriod`; HTTPUpgrade `?ed=` early-data path-strip; HTTP/h2 + tcp-`header.type=http` headers/method; ECH `echForceQuery`; TLS `min/max_version`; mieru `mtu`. `net=kcp`/`mkcp` now returns an explicit "unsupported" error instead of a silent drop (full mKCP transport port deferred).
- **AmneziaWG 1.5** `J1/J2/J3/ITIME` + reserved-bytes parsed and plumbed — **gated** behind a capability constant matching the shipped `amneziawg-go v0.2.18` (which rejects j1-j3/itime; v1.0.4 rejects s3/s4 — both abort the whole `IpcSet` on an unknown key). Flip the constant + `awg_runtime_v1` tag when `core/go.mod` bumps to v1.0.4.

### Fixed (2026-06-23)

- **VLESS `flow=xtls-rprx-vision-udp443`** aliased to `xtls-rprx-vision` (the upstream `sing-vmess` dep accepts only the bare value → the node died at outbound construction). **`encryption=mlkem768x25519plus`** (post-quantum) now surfaces a clear error instead of silently emitting a plaintext-handshake config the server rejects.
- **TUIC `allow_insecure`** was silently lost (`normalizeStr` turns the key into `allow insecure`, which the direct map lookup missed) — now read via `getOneOfN`. **TUIC `alpn`** read from the URI instead of a hardcoded `[h3, spdy/3.1]` override.
- **Shadowsocks-2022 colon-password** (`2022-blake3-*:psk`) no longer truncated to `method=none` — base64 userinfo is now split on the **first** colon only. Plus SS UDP-over-TCP / multiplex / SIP002-escaped-`;`.
- **VMess** no longer force-sets `authenticated_length`/`packet_encoding` (diverged from upstream defaults). **Trojan** colon-passwords no longer truncated. **Hysteria1/2** read `alpn` + bandwidth; removed an insecure "skip-verify when pinSHA256 present" hack. **AmneziaWG `.conf`** import: fixed a dead branch + inverted `isAwg` sign that made every AWG-obfs config emit **plain WireGuard**; plus multi-peer and `MTU`.
- **Restored the dead `xray2sing` test harness** — it had been silently failing since the sing-box upgrade (`json2map_prettystr` unmarshalled expected JSON with a registry-less `context.Background()` → "missing outbound options registry in context"). Fixing it (`libbox.BaseContext`) unmasked and regenerated long-stale fixtures and surfaced the TUIC / SS-2022 bugs above.

### Removed (2026-06-23 — dehiddification)

- **Dead hiddify-lineage crutches** (all parser-set / runtime-never-read → **zero behavior change**): `tls_fragment` — deleted `option/fragment.go` (`TLSFragmentOptions{Size/Sleep/Method/Range}` + its unused `RandBetween`), the dead `DialerOptions.TLSFragment` field, and parser `getFragmentOptions`; native fragmentation is the upstream **route-action** path (`metadata.TLSFragment` → `tf.NewConn`, which is SNI-aware — splits inside the ClientHello domain name, smarter than hiddify's blind byte-size). Also removed `TLSTricks.{PaddingMode,PaddingSize,PaddingSNI}` (kept the live `MixedCaseSNI`), `URLTestOutboundOptions.URLs` (runtime reads only the singular `URL`), and top-level `Options.Custom`. The `//H` hiddify-marker was swept across `option/`: 2 dead fields removed, 6 verified-live kept. Also removed the now-dangling **writers** in `v2/config` (`patchOutboundFragment`, the `EnablePadding` block, the `OutboundDirectFragmentTag` fragment field) that fed those dead options from the app's `tls-tricks` toggles — so the app's **`enable-fragment` / `enable-padding` toggles are now explicit no-ops** (they had been silently non-functional since the sing-box upgrade — the runtime stopped reading `DialerOptions.TLSFragment`). `mixed-sni-case` stays live. Follow-up: drop the dead toggles from the app UI, or re-wire fragmentation to the route-action path if it's wanted.

### Fixed

- **Windows browser proxy-auth bypass — now signature-based, not name-based** (2026-06-14): the `mixed` inbound's per-process auth bypass (browsers skip the 407 login dialog while malware still gets challenged) was matching the connecting process by exe basename (`chrome.exe`) — trivially spoofable by renaming a binary (MITRE T1036.003) or dropping it in a user-writable path. Replaced on Windows with **Authenticode verification**: the connecting exe is resolved (`process.Searcher` → PID → image path) and auth is skipped only if its **basename is a known browser AND it carries a chain-valid signature whose cert subject is a known browser vendor** (Google LLC / Microsoft Corporation / Mozilla Corporation / Brave / Opera / Vivaldi / Yandex / Tor). The name scopes the bypass — many non-browsers share a vendor signer (Office apps are "Microsoft Corporation"-signed, same as Edge), so signature alone would admit them; the signature stops a renamed impostor (name alone is spoofable). A browser missing from the name list just shows the dialog (fail-safe). A self-signed binary merely *claiming* the subject fails the trust-chain check; the random per-install creds remain the real boundary. Chain validation uses `WTD_REVOKE_NONE` (no online CRL/OCSP) so it never blocks on a censored network or routes revocation back through our own authenticated proxy; results cached per exe-path+mtime+size (bounded). New `protocol/mixed/auth_browser_windows.go` (signature gate, reuses vendored `tailscale/util/winutil/authenticode`) + `auth_browser_other.go` (non-Windows keeps the basename/Android-package match — Android package identity is OS-enforced). `process_whitelist` field unchanged (still enables the searcher + drives Android). Cross-compiles clean (`GOOS=windows` + native vet). See `feedback_security_localhost_auth.md`.
- **Subscription translation hardening — ~33 fixes** (2026-06-13): a systematic scan of `xray2sing` (the `vless://`/`vmess://`/`trojan://`/`hysteria2://`/`ss://`/... → sing-box converter) found a whole class of "parameter lost / wrong default → silently broken outbound" bugs (valid JSON, dead connection). All confirmed by running `Ray2Singbox` + `libbox.CheckConfig`. Highlights:
  - **Whole nodes were dropped to null**: `net=h2` (HTTP/2 transport — aliased to `http`) and `net=splithttp` (old name for `xhttp`, still emitted by marzban/old x-ui — aliased to `xhttp`) hit `unknown transport type` and the outbound vanished from the subscription.
  - **Reality** was only applied to `vless`/`naive` — moved into `getTLSOptions` so `vmess`/`trojan` + Reality work too. `+` in `pbk`/`sid` no longer decodes to a space (broke every Reality key with a `+`); base64 userinfo split is gated to `ss://` so it no longer eats trojan passwords / vless UUIDs; `xvmess://`/`svmess://` no longer dropped.
  - **xhttp/transport ALPN**: `xhttp` now defaults `alpn=h2` (Xray xhttp negotiates HTTP/2; empty ALPN fell back to HTTP/1.1 and the handshake silently died — this was the whitelist-bypass-configs-work-in-Happ-but-not-here bug); `grpc`/`quic`/`ws`/`httpupgrade` keep an explicit user ALPN instead of clobbering it. gRPC `service-name`/`grpc-service-name` (dashed keys) now read. SNI falls back to `host` (not the nonexistent `add`) for vless/trojan domain-fronting. `nosni=0` no longer wrongly disables SNI. vmess defaults `fp=chrome` (was sending the detectable Go-default ClientHello).
  - **Per-protocol**: hysteria `obfsParam`/`pinSHA256`, hysteria2 `obfs-password` + port-hopping, tuic `congestion_control`/`udp_relay_mode`, shadowsocks SIP003 plugin split + legacy whole-base64, naive (strip ALPN/insecure/disable_sni that sing-box rejects) + `naive+quic`, mieru port-from-authority + handshake, AmneziaWG obfuscation params (were always emitting plain WG) + `pk@host` guard, WARP license/reserved, ssh empty host_key, http `tls=none` no longer force-enables TLS, socks/http `udp_over_tcp`. Files across `core/xray2sing/ray2sing/`.
- **olcrtc lazy non-primary**: a dead/unreachable olcrtc outbound no longer crashes the whole sing-box instance at startup. olcrtc was the only eager-blocking outbound (it joins a Jitsi room on `Start()`, 30s timeout); any failure aborted the entire box (so a single down Stealth endpoint took out Reality/Naive too). Now the selected (`primary`) olcrtc stays blocking-ready (anti-phantom), while non-selected ones defer their join to first dial (lazy) — a dead unselected endpoint can no longer strand the tunnel. (branches `fix/olcrtc-lazy-nonprimary`; verified on build 40 punching through Megafon LTE.)

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

- **dead-end combos walked back** (2026-05-28 evening): pushed `7bc78559` (blocking + 120s) and `3eea0a2a` (non-blocking + 120s + app tag fix) hoping to support iPhone XR + Megafon LTE — both made things worse. `7bc78559` blocked sing-box service init for 120s on slow handshakes → iOS NE killed the tunnel before init finished, breaking even Reality/Naive. `3eea0a2a` re-introduced the iOS phantom (gstatic probe routes through olcrtc fine, user traffic dies in incomplete handshake). Reverted both — `core/main` HEAD now back on `bb159078` (blocking, 30s timeout), the only known-stable combo. iPhone XR + Megafon LTE remains broken; the right fix lives in pion (TURN-over-TCP / ICE-TCP-only build) — see Wave 19 backlog.
