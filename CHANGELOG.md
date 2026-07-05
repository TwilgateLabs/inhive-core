# Changelog

All notable changes to `inhive-core` (Go DLL/AAR/iOS framework) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Releases are tagged in git; entries below are grouped by date of major changes
(this codebase is rebuilt-and-vendored per `inhive-app` release rather than
shipped standalone).

## [Unreleased]

### Fixed (2026-07-06 — Happ subscription format: real names, hysteria2, no Авто dupes)

Happ exports a subscription as a JSON array of FULL Xray configs (each element carries the node name in a top-level `remarks`, the inner outbound is always tagged generic `proxy`). The importer had three bugs — a live capture (66 configs) produced 105 junk `proxy` entries. All three fixed in `xray2sing/ray2sing/json_ingest.go`:

- **Node names restored — `remarks` is now honored instead of the generic `proxy` tag.** A wrapper object carrying `remarks`/`remark` is treated as one Happ node: its top-level name is stamped over the inner outbound tag, so the list shows `🇳🇱 Netherlands | TCP` etc. instead of `proxy`, `proxy-2`, `proxy-3`.
- **Hysteria2 nodes survive.** Happ exports hy2 as `protocol:"hysteria"` with `streamSettings.hysteriaSettings.version==2` + `auth`; these previously hit the default branch and were skipped. They now rebuild to `hysteria2://auth@host:port?sni=…&alpn=…` (sni/alpn/insecure from `tlsSettings`, salamander obfs when present) and round-trip through the existing hy2 parser. 11 hy2 nodes now import.
- **"Авто" bundles collapse to one node.** Happ's `Wi-Fi | Авто` / `LTE/4G | Авто` configs pack the whole server list as outbounds for client-side smart routing; we used to expand each → dozens of duplicate `proxy` entries. A Happ per-node wrapper now emits exactly the FIRST real proxy outbound (skipping freedom/blackhole/dns locals), matching what the Happ client itself shows.

Array order is preserved (grouped by country). Native sing-box JSON, bare outbound arrays, single-config and Clash/SIP008 ingest are untouched (they carry no `remarks`). New `happ_ingest_test.go` covers names≠proxy, hy2 present, no Авто dupes, order — inline sample + golden replay of the real 66-config capture (`testdata/happ_xpnet.json` → 66 nodes, 11 hy2). `go vet` clean, full ray2sing corpus green.

### Fixed (2026-07-06 — 4.7.1 hotfix: reconnect / ping hang / reality-xhttp)

Three verified root-cause fixes for "ping hangs + reconnect wedges after a disconnect (all OS)" and "reality-xhttp configs never connect":

- **`hcore.Setup` is now idempotent — a fast reconnect no longer leaves the service running with NO gRPC server (RC-2d).** A quick reconnect (Android `VPNService.onStartCommand` → `Mobile.setup` → `hcore.Setup`) hit the `if grpcServer[mode] != nil { return nil }` guard and silently skipped building a new server; a deferred `Mobile.close(4)` → `CloseGrpcServer` then stopped the one server that existed. Result: the service looked "up" but had no gRPC server and Dart hammered a dead channel forever. Setup now graceful-stops the stale server (frees the port, clears the map slot) and builds a fresh one, so it ALWAYS leaves a live server on the requested Mode with no zombie. Safe on first launch (empty map → no-op) and identical on every OS / Mode (Win DLL, Android AAR, iOS NE). Added a `closeGrpcServerLocked` internal so Setup can tear down under the already-held `mu` without self-deadlocking. (`v2/hcore/grpc_server.go`.)
- **Side-instance bring-up now has a hard 8s deadline — a wedged bring-up can no longer hang forever or pile up instances (RC-4).** The honest-ping side-instance (`RunInstanceQuiet` → `runInstanceCore`) started the probe budget only AFTER the instance was up; the bring-up itself (`StartOrReloadServiceOptions` binds the port + inits outbounds/DNS and is NOT context-cancellable) had no ceiling, so a stuck bind / DNS settle leaked a running side-instance forever. Bring-up now runs in a goroutine raced against an 8s `bringUpBudget`; on timeout it returns immediately with a bring-up-classified error (→ `bring_up_failed=true`, the app shows blank, never a red ×) and the detached worker closes any instance that finishes starting after the deadline, so nothing leaks. Also plugged two pre-existing leaks on the settle-cancel path. Unit tests cover the deadline path + the bring-up-vs-dead classification. (`v2/hcore/independent_instance.go`.)
- **XHTTP `mode:"auto"` now resolves to a concrete dial mode — reality-xhttp configs connect again.** Our fork lacked `GetNormalizedMode`, so `mode:"auto"` (the default the xray2sing parser emits) and empty mode fell through to the packet-up POST loop while Xray dials reality-xhttp as stream-one → the connection was dead on arrival. Resolution now mirrors Xray-core: reality present → `stream-one`, reality + `downloadSettings` → `stream-up`, otherwise `packet-up`. Explicit modes pass through untouched and non-reality auto stays packet-up (no regression for plain xhttp). REALITY is detected via a new `tls.IsRealityClientConfig` helper (unwraps the kTLS wrapper). Unit tests cover every branch. (submodule `inhive-sing-box`: `transport/v2rayxhttp/client.go`, `common/tls/reality_detect*.go`.)

Build note: `go vet` clean, host + `GOOS=windows` cross-build clean, unit tests green. DLL/AAR rebuild pending on the Win server (AAR/android cronet lib needs the NDK toolchain there).

### Changed (2026-07-05 — cronet-go → Chromium 148, sing 0.8.9)

Coordinated dependency bump of the NaiveProxy engine (the previous attempt failed because it pulled cronet-go `@main` — the *source* branch, which has no generated headers or prebuilt libs; the consumable snapshots live on the `go` publish branch):

- **cronet-go April `e4926ba` (Chromium 147.0.7727.49) → `go`-branch tip `b3eec813` (Chromium 148.0.7778.96, built from `ec86c149`).** Main module, `all`, and all 29 prebuilt `lib/*` slices (ios/android/darwin/windows/linux) bumped to the same publish point — Go code and static `libcronet.a` are one Chromium version again. Brings the Apr-15 "Reduce netErrorInfo memory usage" fix (relevant to the iOS NE jetsam budget) and Chromium 148's QUIC receive-window fixes. The Jul-2 "Fix quic not disabled" one-liner is main-only with no published `go`-branch build yet — picked up on the next upstream publish.
- **sing 0.8.4 → 0.8.9** (dragged in by cronet-go). Diff is 7 bugfix commits — UoT read/write race fixes, interface-finder fix, freelru lifetime fixes, additive `Registry.Clone`/`ExtendContext` — zero API breaks: the whole fork + core compile unchanged. purego 0.9.1 → 0.10.0 alongside (Windows/Linux dynamic loader path).
- `sing-box/.github/CRONET_GO_VERSION` → `b3eec813...` (Windows `extract-lib` path; note the new extract-lib resolves the lib module via `git ls-remote` of the `go` branch tip, which currently equals our pin).
- Verified: full-tags build clean, `go vet ./v2/hcore/...` clean, `make ios` EXIT 0 — device slice 121MB with 1045 `Cronet_` symbols and the `148.0.7778.96` version string embedded. Android AAR / Windows DLL rebuild still pending on the Win server (cross-typecheck for `GOOS=windows` + `with_purego` passes).

### Changed (2026-07-05 — honest per-config ping: endpoints + error classification)

`UrlTestConfig` (the honest per-server side-instance probe) now measures "does the internet actually work through this config" for every protocol, and stops reporting our-side failures as a dead server:

- **WireGuard / AmneziaWG probe through the endpoint.** sing-box 1.13 moved these to `endpoints[]`, so the handler used to bail with "no outbounds" → they were never honestly pinged. `probeTag()` now picks the endpoint tag first (they *are* the exit), driving the probe through the endpoint dialer — the same pattern the WireGuard endpoint's own `readyChecker` uses. For an endpoint-only config the outbounds hold only `select`/`direct`/`block`, so the old "first non-group outbound" rule would have picked `direct` and measured the raw uplink (false green) — endpoint-first avoids that.
- **Bring-up vs probe error classification.** New `UrlTestConfigResponse.bring_up_failed`: everything before the first probe attempt (config parse, no exit, `RunInstanceQuiet`, not-ready, tag lookup, panic) is flagged bring-up — the app shows blank ("couldn't test"), not a red ×. Only a failure of the probe itself *through* a live outbound is a real dead verdict. A cold-phone bring-up timeout or a port-bind race is no longer misreported as a down server. Backward-compatible (old clients ignore the field; an old core leaves it false = prior behaviour).

Follow-ups from the full-app code review, all aimed at the iOS Network Extension's ~50MB jetsam budget:

- **iOS build tags: `with_dhcp` dropped** (DHCP DNS discovery can't work inside an NE). NOTE: the same commit also excluded `with_naive_outbound` from iOS, but that was **reverted on 2026-07-04** — NaiveProxy is the strongest RU anti-DPI fallback, worked on iOS since build 44, and the jetsam risk that motivated the removal is theoretical (empirically fine build 44→72) and already covered by the dial-cap/thread-cap/mem-ceiling hardening. `IOS_TAGS` once again includes naive. (`Makefile`.)
- **`make ios IOS_TARGET=ios`** — device-only xcframework builds; the simulator slice (241MB of 362MB, 2× build time) is now opt-out for release runs. Default behaviour unchanged.
- **`debug.FreeOSMemory()` after mobile start-up.** Config parsing + rule-set compilation leave 3-8MB of garbage that the Go scavenger returns lazily, while jetsam judges `phys_footprint` immediately; the pages are now returned right after the core reports STARTED (iOS/Android). Upstream's `cmd_run.go` does the same.
- **`readStatus` no longer opens goleveldb every second.** The 1/sec system-info stream re-read `lastStartRequestName` via a full DB open/close on every tick until traffic passed 1MB — constant allocation churn under the 32MB memory limit. The name is now cached at `StartService` (one cold-start DB read at most, negative result cached too). (`v2/hcore/start.go`, `commands.go`.)
- **`heartbeat.log` size-cap rotation.** The App Group diagnostic log grew unbounded across sessions; it now rotates once at start past 1MB, keeping a single `.1` backup — same non-fatal pattern as the box.log cap. (`v2/hcore/grpc_server.go`.)

### Fixed (2026-07-02 — iOS crash/abort hardening under sustained upstream loss)

When an upstream exit node went fully unreachable (a null-routed server produced a storm of failing dials + DNS lookups), the iOS core could hit an unrecoverable Go runtime fatal (`SIGABRT`, re-raised — not a catchable panic) instead of degrading gracefully. This closes the two off-heap / thread fatal surfaces that the 4.6.1 memory hardening didn't cover:

- **Concurrent outbound-dial cap.** Every app socket becomes a TUN flow that blocks in the dialer for the full TCP-connect timeout when the upstream is down; under a retry storm these pile up, each holding a goroutine stack + cached buffer + gVisor endpoint — off-heap `phys_footprint` that the Go memory limit does not bound and that iOS jetsam kills the extension for. A counting semaphore (`maxConcurrentDials = 256`, mirroring the existing DNS-exchange cap) now bounds in-flight blocking dials; on saturation the flow is dropped with a rate-limited log and a `dialsDropped` counter, exactly like the DNS path. (`route/conn.go`.)
- **iOS OS-thread cap.** The Go runtime's default 10000-thread ceiling was never lowered; each cgo-blocking dial can hold a thread, so a dial storm could reach `fatal error: thread exhaustion` — an unrecoverable `SIGABRT` with no goroutine-panic frame. `runtimeDebug.SetMaxThreads(512)` on the iOS extension converts that into an early, deterministic, loggable failure — and combined with the dial cap it should never be reached. (`experimental/libbox/memory.go`.)

### Added (2026-06-26 — universal subscription formats)

Providers serve different container formats based on the client's User-Agent: a client that presents as sing-box gets a sing-box JSON config, a clash client gets Clash YAML, others get base64 share-links — and the protocol set can differ per format (e.g. some only include hysteria2 in the sing-box/Shadowrocket variants). The parser now ingests the two formats we were missing, so we can consume whatever a provider sends instead of falling back to a reduced share-link set.

- **Native sing-box JSON ingest.** Outbounds keyed by `type` (vs Xray's `protocol`) with flat fields and nested `tls`/`transport` are now rebuilt into share-links and parsed through the same single per-protocol pipeline (hysteria2, vless incl. reality, vmess, trojan, shadowsocks, tuic). Group/system outbounds (`selector`/`urltest`/`direct`/`block`) are filtered, never turned into fake nodes. (`singbox_ingest.go`, dispatched from `json_ingest.go` on the `type` key before the SIP008 check.)
- **Clash / Clash.Meta YAML ingest.** A `proxies:` list (clash field names: `port`/`cipher`/`servername`/`skip-cert-verify`/`network`+`*-opts`/`reality-opts`) is transcoded the same way; `proxy-groups`/`rules` are ignored. (`clash_ingest.go`; `yaml.v3` was already in the module graph — no new dependency.)
- Both are guarded by round-trip tests; everything still funnels through the one URI-parser source of truth, so list, ping and connect can't disagree.

### Fixed (2026-06-26 — ping reliability)

The honest per-server ping was truthful but brittle: it spun a brand-new side-instance and made a *single* cold probe, so any first-attempt hiccup — a cold DNS answer, one dropped SYN, a TLS/WebSocket handshake racing the instance's 250 ms settle — was reported as "dead". Pinging the same working server a few times could show offline, offline, offline, then online, which read as the app lying. A comparison of how other clients ping (sing-box's own warm urltest group, Clash.Meta/Mihomo) showed the difference: they keep a warm instance and/or never declare a node dead on one failed probe. We now do the cheap, equivalent thing.

- **Best-of-N probe on the same warm side-instance.** `UrlTestConfig` now probes up to three times within the same time budget instead of once, reusing the already-running instance so attempts 2–3 ride warm OS DNS/route state; the first attempt gets the largest slice for the cold handshake. The first success wins and only if all attempts fail is the server reported dead. This is what removes the "3× offline then online" flicker — a working server answers on the first tap. (`url_test_config.go`, `splitProbeBudget`, with a unit-test guard.)
- **Side-instances no longer clobber the process-global logger.** Each box bring-up unconditionally reset the global std logger; under a parallel ping-all that is a write/write data race on an unsynchronised package global. Only the main box owns it now, so concurrent ping probes never touch it (`daemon/instance.go`).

### Fixed (2026-06-26 — foreign-subscription compatibility audit)

A differential audit of our config parser against Xray/Happ found a class of configs that imported as a valid node but silently didn't work — or worked insecurely. This was the third "our universal client doesn't support X" regression, so the fixes all land in the single Go parser (`ray2sing`) — both the ping and the live connection get them at once — and a new canonical corpus test plus a cross-path equivalence test (`ray2sing_test/compat_corpus_test.go`) now guard every case so the class can't silently come back.

- **WebSocket / httpupgrade over TLS no longer breaks when the subscription advertises `h2` in ALPN.** A foreign "обход" config (vless+ws, `alpn=http/1.1,h2`) worked in Happ but EOF'd here: the server negotiated HTTP/2 at TLS time, and an HTTP/1.1 WebSocket upgrade can't run over h2. The per-transport ALPN clamp that should have prevented this was dead code — a `getOneOfN` argument bug (`getOneOfN(decoded, "net")` passed the key as the default with no keys, so the transport was never detected), so the raw ALPN including `h2` went to the wire. Now ws/httpupgrade clamp to `http/1.1` and grpc/h2 to `h2`, matching Xray. Fixes the whole ws+TLS class, not one node.
- **TUIC to a hostname server no longer silently disables SNI and TLS certificate verification.** A TUIC node with no explicit `sni=` was force-setting `disable_sni`, breaking SNI-routed fronts and quietly turning off cert checking. SNI now falls back to the connect host; only a bare-IP endpoint omits it (like hysteria2).
- **Shadowsocks SIP002 passwords with `.`, `,`, `?`, brackets, or url-safe base64 are no longer dropped.** A too-narrow character whitelist silently discarded valid credentials, leaving the method as a raw base64 blob (broken node). Replaced with decode-then-validate.
- **JSON subscriptions no longer drop TCP HTTP-header obfuscation or XHTTP split-download settings.** Foreign providers ship full Xray JSON, not share-links; the JSON-ingest path was silently dropping `tcpSettings.header` and the xhttp `extra` block. Both now transcode faithfully — asserted by the cross-path test (JSON and share-link forms of one config must produce an identical outbound).
- **Hysteria2 explicit `alpn=` is now honored** (it was parsed, then ignored).
- **HTTPS proxy `insecure=false` now means verify** (it was inverted — anything but a literal `0` disabled verification).
- **uTLS fingerprint is kept for `nosni=1` nodes and correctly disabled for QUIC/h3** (where uTLS has no HTTP/3 ClientHello — previously only the xhttp case was guarded).
- **Trojan with `flow=xtls-rprx-vision` is rejected with a clear error** instead of silently building a plain Trojan-TLS node that dies in the handshake (sing-box's Trojan has no Vision flow field).

### Added (2026-06-26 — honest per-server ping)

- **New `UrlTestConfig` gRPC method for honest server ping.** The app can now ask the core to ping a single server *honestly*, regardless of VPN state: the core spins a throwaway side-instance from a one-server config, runs a real HEAD probe to `generate_204` *through that server's outbound*, measures the round-trip, and tears the instance down — without touching the main VPN box (same isolated `RunInstanceQuiet` scaffolding as BootstrapFetch, and the shared `urltest` probe). A working server returns its real latency; a dead or DPI-blocked one returns an error — no false "reachable". This is what lets the app retire its TCP-connect ping, which only checked whether a TCP port was open and so lied for Reality (port open but protocol blocked → fake green) and for hysteria2/QUIC (no TCP listener on the UDP port → fake blank). Honest for hysteria2/QUIC and Reality alike. The probe is driven through the config's **first non-group (exit) outbound** explicitly (via `urltest.URLTest`), skipping the `select` selector the app puts at `outbounds[0]` and not using the side-instance's default route — so chained transports measure end-to-end correctly (e.g. UTProto, which is a VLESS whose `detour` is a FakeTLS helper: probing the selector or the default route fails with EOF; dialing the exit VLESS drives the whole chain). Verified with runtime tests (live outbound → real ms; unroutable outbound → error + 0 ms; live UTProto chain → real ms, dead UTProto backend → honest error — no false positive).

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
