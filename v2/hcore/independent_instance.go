// independent_instance.go — standalone proxy instances for testing and extensions.
package hcore

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/twilgate/inhive-core/v2/config"
	"golang.org/x/net/proxy"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

// getRandomAvailblePort: best-effort port allocation. There IS a TOCTOU race
// between Close() and sing-box bind — under heavy parallel BootstrapFetch load
// two side-instances may pick the same port. Caller of RunInstance/Quiet should
// retry on bind failure. Mitigated by binding to 127.0.0.1 specifically (not
// :0) which narrows the race window vs all-interfaces.
func getRandomAvailblePort() (uint16, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("getRandomAvailblePort: %w", err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	listener.Close()
	return port, nil
}

// sideInstanceContext returns the context a side-instance box must run under.
//
// On Android the ping / bootstrap side-instance MUST carry the platform
// interface so its outbound dialer protects its sockets via
// VpnService.protect(fd). Without it, every dial returns EPERM
// ("operation not permitted") while the main TUN is up: the un-protected
// side-instance socket is captured by the VPN route and the kernel refuses the
// connect, so every server false-reads as dead (confirmed on-device 2026-07-08:
// `dial tcp <srv>: operation not permitted`, and even `lookup <host>: dial tcp
// 9.9.9.9:443: operation not permitted` for the multi-DoH resolver). This is the
// exact registration the main tunnel does (start.go StartService).
//
// Gated to Android + iOS-app-process (see the inline comment below for the full
// iOS rationale — 4.8.0+142 post-mortem). Windows' wintun does not EPERM
// own-process sockets, and the iOS NE process's sockets already bypass its own
// tun — both stay byte-identical (no registration). baseContext
// (libbox.FromContext) does NOT pre-register adapter.PlatformInterface, so
// MustRegister here is a first registration (no double-register panic).
// See [[core-crash-fixes-ping-sweep]] neighbour work.
func sideInstanceContext(serviceCtx context.Context) context.Context {
	if static.globalPlatformInterface == nil {
		return serviceCtx
	}
	// libbox.FromContext (baseContext) registers the platform `type:local` DNS
	// transport when the platform interface exposes a LocalDNSTransport.
	//
	// InHive P3 (2026-07-12): do this on iOS too (was Android-only). On a fail-closed
	// whitelist the probe's DoH-over-IP fan is dropped, and the native darwin
	// `type:local` falls back to the Go resolver → /etc/resolv.conf unreadable in the
	// iOS sandbox → default nameserver [::1]:53 → connection refused. So a side-instance
	// with a DOMAIN server address (e.g. cdn.inhive.net) has NO working resolver and the
	// dial dies before the outbound — the backend false-deads (×), while its literal-IP
	// twin has nothing to resolve and pings green. Routing `type:local` to the platform
	// resolver (iOS: Swift LocalResolver → getaddrinfo on the underlying non-VPN network,
	// bypassing TUN) makes the probe resolve the server domain EXACTLY like the live
	// tunnel. gstatic / payload hosts resolve REMOTELY at the exit, so only the server
	// address needed this. See the IP-vs-domain probe-divergence trace.
	ctx := libbox.FromContext(serviceCtx, static.globalPlatformInterface)
	// Register the PlatformInterface adapter for the side-instance on Android and
	// on iOS-in-the-APP-process (standalone core). NOT under the NE.
	//   - Android: protect(fd) via VpnService.protect stops the side-instance
	//     socket being captured by the main TUN route → EPERM (device-log 2026-07-08).
	//   - iOS app process (added 2026-07-22): the OLD assumption ("no-TUN standalone
	//     never loops own-process sockets through a TUN, so it's unnecessary") is
	//     WRONG when the SYSTEM VPN (our NE PacketTunnelProvider) is up — it holds
	//     the default route, so the app-process standalone's probe dials get captured
	//     by that utun and egress THROUGH the tunnel instead of the phone's real
	//     network → per-server pings of a SECOND subscription measured reachability
	//     from the exit, not the phone → false × for phone-reachable servers
	//     (4.8.0+140/142 regression). Without a platform interface the side-instance
	//     box builds its OWN tun.DefaultInterfaceMonitor, which reports the system
	//     default route = utunN while the VPN is up, and auto_detect_interface binds
	//     probe dials INTO the tunnel (device diag 2026-07-22: probe errors carry no
	//     "dial en0 (17)" prefix + the NE's box.log sees the probes' DNS). Registering
	//     the PlatformInterface routes the side-instance dialer through the platform
	//     monitor (StandalonePlatformInterface reports the PHYSICAL interface — utun
	//     filtered via prohibitedInterfaceTypes:[.other]) → IP_BOUND_IF(en0/pdp_ip)
	//     bypasses the tunnel (works while includeAllNetworks stays false).
	//     Byte-identical to the NE's own dial path, whose en0 dials are proven
	//     working in device logs. See [[debug_ios_ping_stale_green_ne_reroute_2026_07_22]].
	//   - iOS NE process EXCLUDED on purpose: NE-process sockets already bypass the
	//     NE's own tun (Apple guarantee) so the bind buys nothing there, and the NE's
	//     InhivePlatformInterface holds a SINGLE NWPathMonitor — a side-instance
	//     (speedTest at VPN-on runs INSIDE the NE) calling start/closeDefaultInterface-
	//     Monitor on it would cancel/replace the LIVE TUNNEL's monitor and break the
	//     tunnel's dial routing. Keep NE side-instances byte-identical to before.
	if C.IsAndroid || (C.IsIos && !static.globalPlatformInterface.UnderNetworkExtension()) {
		service.MustRegister[adapter.PlatformInterface](ctx, libbox.WrapPlatformInterface(static.globalPlatformInterface))
	}
	return ctx
}

func RunInstanceString(ctx context.Context, inhiveSettings *config.InhiveOptions, proxiesInput string) (*InhiveInstance, error) {
	if inhiveSettings == nil {
		inhiveSettings = config.DefaultInhiveOptions()
	}

	singconfigs, err := config.ParseConfig(ctx, &config.ReadOptions{Content: proxiesInput}, true, inhiveSettings, false)
	if err != nil {
		return nil, err
	}
	return RunInstance(ctx, inhiveSettings, singconfigs)
}

// RunInstanceRaw brings up a side-instance from a FULLY-BUILT sing-box config
// (the app's own buildMultiServerConfig / buildSingboxConfig output) WITHOUT
// running it through the legacy hiddify InhiveOptions translator (config.BuildConfig
// with EnableFullConfig=false). This is the same raw path the main tunnel uses
// (buildconfighelper.go: EnableRawConfig=true → config.ReadSingOptions) — the
// probe now executes in the SAME configuration semantics it will run in for real:
// the app's multi-DoH directDns fan, its DNS rules, its selector default = the
// probed server, its exact outbounds/endpoints. Nothing is silently re-derived.
//
// WHY IT MATTERS (ping honesty). The old side-instance path replaced the app's DNS
// block with udp://1.1.1.1:53 and injected a round-robin balancer as the selector
// default. On a hostile network (RU LTE RST-blocking UDP:53) a domain-addressed
// server failed to resolve → dial error → tested-dead ×, while the REAL tunnel
// (multi-DoH) connected fine. And warm WG/AWG probes resolved gstatic through a
// RANDOM subscription server (balancer default). Both false-deads vanish once the
// probe runs the app's config verbatim.
//
// sanitizeSideInstance strips only what a side-instance must not have (TUN,
// clash-api, cache-file) and rewrites a listen inbound to a random port; DNS,
// route, outbounds and endpoints are left byte-for-byte as the app built them.
func RunInstanceRaw(ctx context.Context, opts *option.Options) (instance *InhiveInstance, err error) {
	defer config.RecoverPanicToError("RunInstanceRaw", func(panicErr error) { err = panicErr })
	return runInstanceCore(ctx, func(serviceCtx, bringUpCtx context.Context) (*InhiveInstance, error) {
		return startRawSideInstance(serviceCtx, bringUpCtx, opts)
	})
}

// bringUpBudget caps how long a side-instance is allowed to spend coming up
// (config build + service start + outbound/DNS init + settle) before we give up
// and tear it down. The service's own Start() path binds ports and initialises
// outbounds WITHOUT honouring context cancellation, so a wedged bring-up (a port
// bind deadlock, a DNS settle that never returns) would otherwise hang forever,
// pile up side-instances and hold resources. 8s is a generous ceiling: a healthy
// cold-phone bring-up finishes in well under 2s, so this only ever fires on a
// genuine hang — and it is deliberately INDEPENDENT of the caller's probe budget
// (the probe timeout measures the server; this measures OUR ability to run the
// test). A timeout here surfaces as bring_up_failed on the ping path → the app
// shows blank, never a red ×.
const bringUpBudget = 8 * time.Second

func RunInstance(ctx context.Context, inhiveSettings *config.InhiveOptions, singconfig *option.Options) (instance *InhiveInstance, err error) {
	defer config.RecoverPanicToError("RunInstance", func(panicErr error) { err = panicErr })
	hservice, err := runInstanceCore(ctx, func(serviceCtx, bringUpCtx context.Context) (*InhiveInstance, error) {
		return runInstanceCoreBlocking(serviceCtx, bringUpCtx, inhiveSettings, singconfig)
	})
	if err != nil {
		return nil, err
	}
	// Warm-up probe — verifies that the freshly started side-instance can actually
	// reach the open Internet through its outbound chain. Used by cmd_instance and
	// profile_repository which want a hard "is this config alive" signal.
	hservice.PingCloudflare()
	return hservice, nil
}

// RunInstanceQuiet is the same as RunInstance but skips the PingCloudflare end-of-boot
// probe. The probe targets cp.cloudflare.com which is blocked on RU LTE carriers
// (Megafon / Beeline / MTS / Tele2 / Yota) — the 4-second timeout would be charged
// to every BootstrapFetch call on our main audience. Callers that already plan to
// drive their own HTTP request through the side-instance (Wave 13D BootstrapFetch)
// do not need the probe and should use this variant.
func RunInstanceQuiet(ctx context.Context, inhiveSettings *config.InhiveOptions, singconfig *option.Options) (instance *InhiveInstance, err error) {
	defer config.RecoverPanicToError("RunInstanceQuiet", func(panicErr error) { err = panicErr })
	return runInstanceCore(ctx, func(serviceCtx, bringUpCtx context.Context) (*InhiveInstance, error) {
		return runInstanceCoreBlocking(serviceCtx, bringUpCtx, inhiveSettings, singconfig)
	})
}

// runInstanceCore brings a side-instance up under a hard deadline. The actual
// bring-up (via `build`) runs in a goroutine because the underlying service
// Start() is not context-cancellable; we race it against bringUpBudget. On timeout
// we return a bring_up-classified error immediately, and the goroutine closes
// whatever instance it eventually produces so nothing leaks (leak-safe: exactly
// one of the two owners closes the instance).
//
// `build(serviceCtx, bringUpCtx)` is the caller-supplied synchronous bring-up:
// the legacy translated path (runInstanceCoreBlocking) or the raw path
// (runInstanceCoreBlockingRaw). Both share this identical race/leak machinery.
func runInstanceCore(ctx context.Context, build func(serviceCtx, bringUpCtx context.Context) (*InhiveInstance, error)) (*InhiveInstance, error) {
	type result struct {
		inst *InhiveInstance
		err  error
	}
	// Unbuffered: the worker's send only completes if the caller is still waiting
	// to receive. If the caller has already timed out (returned), the send never
	// succeeds and the worker falls to its cleanup branch — this is how we avoid
	// leaking an instance that finished starting AFTER the deadline. (A buffered
	// channel would silently accept the send and skip cleanup.)
	done := make(chan result)
	// Derive a cancellable child so BuildConfig / the settle select observe the
	// deadline too (they DO honour ctx); Start() itself is un-cancellable, which
	// is exactly why we also need the goroutine race below.
	bringUpCtx, cancel := context.WithTimeout(ctx, bringUpBudget)
	defer cancel()

	go func() {
		var inst *InhiveInstance
		var err error
		// The worker is detached — once the caller times out it runs alone, so a
		// panic here (bad config, nil deref) must be recovered locally or it would
		// crash the whole host process, not just fail the probe.
		func() {
			defer config.RecoverPanicToError("runInstanceCore.worker", func(panicErr error) { err = panicErr })
			inst, err = build(ctx, bringUpCtx)
		}()
		select {
		case done <- result{inst, err}:
			// Delivered to the still-waiting caller — caller owns inst.Close().
		case <-bringUpCtx.Done():
			// Caller already gave up (timeout / parent cancel). We own cleanup:
			// close any instance that finished starting after the deadline.
			if inst != nil {
				_ = inst.Close()
			}
		}
	}()

	select {
	case r := <-done:
		return r.inst, r.err
	case <-bringUpCtx.Done():
		return nil, fmt.Errorf("side-instance bring-up exceeded %s: %w", bringUpBudget, bringUpCtx.Err())
	}
}

// runInstanceCoreBlocking does the synchronous bring-up. `serviceCtx` is the
// LONG-LIVED context handed to the started service (it must outlive bring-up —
// binding it to the bring-up deadline would kill a healthy instance the moment
// runInstanceCore returns). `bringUpCtx` carries the bring-up deadline and is
// used only for the deadline-aware steps (config build, settle) that honour ctx.
func runInstanceCoreBlocking(serviceCtx, bringUpCtx context.Context, inhiveSettings *config.InhiveOptions, singconfig *option.Options) (*InhiveInstance, error) {
	if inhiveSettings == nil {
		inhiveSettings = config.DefaultInhiveOptions()
	}
	inhiveSettings.EnableClashApi = false
	port, err := getRandomAvailblePort()
	if err != nil {
		return nil, err
	}
	inhiveSettings.InboundOptions.MixedPort = port
	inhiveSettings.InboundOptions.EnableTun = false
	inhiveSettings.InboundOptions.EnableTunService = false
	inhiveSettings.InboundOptions.SetSystemProxy = false
	inhiveSettings.InboundOptions.TProxyPort = 0
	inhiveSettings.InboundOptions.DirectPort = 0
	inhiveSettings.InboundOptions.RedirectPort = 0
	inhiveSettings.Region = "other"
	inhiveSettings.BlockAds = false
	inhiveSettings.LogFile = os.DevNull
	// BuildConfig adds a balancer outbound — strategy must be non-empty.
	if inhiveSettings.BalancerStrategy == "" {
		inhiveSettings.BalancerStrategy = "round-robin"
	}

	finalConfigs, err := config.BuildConfig(bringUpCtx, inhiveSettings, &config.ReadOptions{Options: singconfig})
	if err != nil {
		return nil, err
	}

	// Bootstrap side-instance: use a no-op PlatformHandler so box does NOT set
	// options.PlatformLogWriter, which would enable CacheFile and conflict with
	// the main instance's exclusive lock on data/clash.db.
	if err := libbox.CheckConfigOptions(finalConfigs); err != nil {
		return nil, err
	}
	svc := daemon.NewStartedService(daemon.ServiceOptions{
		Context:             sideInstanceContext(serviceCtx),
		Debug:               static.debug,
		LogMaxLines:         0,
		Handler:             &noopPlatformHandler{},
		NoPlatformLogWriter: true,
	})
	if err := svc.StartOrReloadServiceOptions(*finalConfigs); err != nil {
		return nil, err
	}
	instance := svc

	// Settle delay — даём time для async init outbounds. Honour bring-up deadline
	// (раньше hardcoded 250ms блокировал даже когда caller отменил context). If the
	// deadline fires here the service is already started, so we MUST close it before
	// bailing — otherwise a wedged bring-up would leak a running side-instance.
	select {
	case <-time.After(250 * time.Millisecond):
	case <-bringUpCtx.Done():
		_ = instance.CloseService()
		return nil, bringUpCtx.Err()
	}
	return &InhiveInstance{
		StartedService: instance,
		ListenPort:     inhiveSettings.InboundOptions.MixedPort,
	}, nil
}

// startRawSideInstance starts `opts` AS-IS (no legacy translation), after
// sanitizeSideInstance strips TUN / clash-api / cache-file and rewrites a listen
// inbound to a random port. Mirrors runInstanceCoreBlocking's start + settle +
// leak-safe teardown. Returns the SOCKS/mixed listen port in ListenPort so
// BootstrapFetch's ContentFromURL can dial it; 0 if the config exposes no listen
// inbound (ping probes never use the inbound — they drive the outbound dialer
// directly via probeThroughDetour — so a probe-only config with no inbound is
// fine).
func startRawSideInstance(serviceCtx, bringUpCtx context.Context, opts *option.Options) (*InhiveInstance, error) {
	if opts == nil {
		return nil, fmt.Errorf("nil options")
	}
	listenPort, err := sanitizeSideInstance(opts)
	if err != nil {
		return nil, err
	}
	// Same no-op PlatformHandler + NoPlatformLogWriter rationale as the translated
	// path: keep the box off data/clash.db (main instance holds the exclusive lock).
	if err := libbox.CheckConfigOptions(opts); err != nil {
		return nil, err
	}
	svc := daemon.NewStartedService(daemon.ServiceOptions{
		Context:             sideInstanceContext(serviceCtx),
		Debug:               static.debug,
		LogMaxLines:         0,
		Handler:             &noopPlatformHandler{},
		NoPlatformLogWriter: true,
	})
	if err := svc.StartOrReloadServiceOptions(*opts); err != nil {
		return nil, err
	}
	instance := svc

	// Settle delay — identical to the translated path: give async outbound init a
	// beat, honour the bring-up deadline, and close a wedged instance before bailing.
	select {
	case <-time.After(250 * time.Millisecond):
	case <-bringUpCtx.Done():
		_ = instance.CloseService()
		return nil, bringUpCtx.Err()
	}
	return &InhiveInstance{
		StartedService: instance,
		ListenPort:     listenPort,
	}, nil
}

// sanitizeSideInstance strips from a fully-built app config ONLY what a
// side-instance must not carry, mutating opts in place. It deliberately does NOT
// touch dns / route / outbounds / endpoints — that is the whole point of the raw
// path: the probe runs the app's config verbatim (its multi-DoH directDns fan, its
// selector default = the probed server), so a green ms means the real tunnel would
// work and a red × means it is genuinely dead.
//
//   - clash-api OFF + cache-file OFF (experimental): the API port would collide
//     with the main box and cache-file would fight for data/clash.db's lock.
//   - TUN inbounds dropped: a side-instance must never touch the system network
//     stack (the main VPN box owns TUN); leaving it would also demand elevated
//     capabilities the probe path does not have.
//   - the FIRST listen-based inbound (mixed/socks/http) is repointed to a random
//     127.0.0.1 port so BootstrapFetch's SOCKS dial has a target and two
//     side-instances never fight for the same port. If the config has no listen
//     inbound (a pure probe config), none is added — probes don't use it.
//
// Returns the chosen listen port (0 when there is no listen inbound).
func sanitizeSideInstance(opts *option.Options) (uint16, error) {
	// Experimental: clash-api and cache-file off. Keep any other experimental
	// fields the app set (v2ray stats etc. — harmless in a side-instance).
	// InHive P0 (2026-07-12): monitoring OFF — паразитный OutboundMonitoring в
	// side-instance гоняет конкурирующие URL-тесты через тот же outbound, что
	// меряет проба, и на общем xmux h2-клиенте (xhttp) травит транспорт →
	// io.ErrClosedPipe → false-×. box.go пропускает создание при Disabled=true.
	if opts.Experimental == nil {
		opts.Experimental = &option.ExperimentalOptions{}
	}
	opts.Experimental.ClashAPI = nil
	opts.Experimental.CacheFile = nil
	if opts.Experimental.Monitoring == nil {
		opts.Experimental.Monitoring = &option.MonitoringOptions{}
	}
	opts.Experimental.Monitoring.Disabled = true

	// Drop TUN inbounds; rewrite the first listen inbound to a random port.
	var listenPort uint16
	kept := make([]option.Inbound, 0, len(opts.Inbounds))
	portAssigned := false
	for _, inb := range opts.Inbounds {
		if inb.Type == C.TypeTun {
			continue // side-instance never owns TUN
		}
		if !portAssigned {
			if lw, ok := inb.Options.(option.ListenOptionsWrapper); ok {
				port, err := getRandomAvailblePort()
				if err != nil {
					return 0, err
				}
				lo := lw.TakeListenOptions()
				lo.ListenPort = port
				// Force loopback: a side-instance must not expose a proxy on a
				// routable interface.
				lo.Listen = common.Ptr(badoption.Addr(netip.MustParseAddr("127.0.0.1")))
				lw.ReplaceListenOptions(lo)
				inb.Options = lw
				listenPort = port
				portAssigned = true
			}
		}
		kept = append(kept, inb)
	}
	opts.Inbounds = kept
	return listenPort, nil
}

// dialer, err := s.libbox.GetInstance().Router().Dialer(context.Background())

func (s *InhiveInstance) Close() error {
	return s.StartedService.CloseService()
}

func (s *InhiveInstance) GetContent(url string) (string, error) {
	return s.ContentFromURL("GET", url, 10*time.Second)
}

func (s *InhiveInstance) ContentFromURL(method string, url string, timeout time.Duration) (string, error) {
	if method == "" {
		return "", fmt.Errorf("empty method")
	}
	if url == "" {
		return "", fmt.Errorf("empty url")
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return "", err
	}

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", s.ListenPort), nil, proxy.Direct)
	if err != nil {
		return "", err
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if body == nil {
		return "", fmt.Errorf("empty body")
	}

	return string(body), nil
}

func (s *InhiveInstance) PingCloudflare() (time.Duration, error) {
	return s.Ping("http://cp.cloudflare.com")
}

func (s *InhiveInstance) PingAverage(url string, count int) (time.Duration, error) {
	if count <= 0 {
		return -1, fmt.Errorf("count must be greater than 0")
	}

	var sum int64
	realCount := 0
	for i := 0; i < count; i++ {
		delay, err := s.Ping(url)
		if err == nil {
			realCount++
			sum += delay.Milliseconds()
		} else if realCount == 0 && i > count/2 {
			return -1, fmt.Errorf("ping average failed")
		}
	}
	if realCount == 0 {
		// Все пинги failed — возвращаем error, иначе division by zero ниже.
		return -1, fmt.Errorf("all %d pings failed", count)
	}
	// time.Duration(sum) is in nanoseconds; we have ms — multiply BEFORE divide
	// to avoid integer truncation (sum=15ms, count=2 → 7.5ms not 7ms).
	return time.Duration(sum) * time.Millisecond / time.Duration(realCount), nil
}

func (s *InhiveInstance) Ping(url string) (time.Duration, error) {
	startTime := time.Now()
	_, err := s.ContentFromURL("HEAD", url, 4*time.Second)
	if err != nil {
		return -1, err
	}
	duration := time.Since(startTime)
	return duration, nil
}

// noopPlatformHandler implements daemon.PlatformHandler with no-ops.
// Used for bootstrap side-instances where we don't want a real handler
// but also can't pass nil (daemon calls handler methods unconditionally).
type noopPlatformHandler struct{}

func (*noopPlatformHandler) ServiceStop() error                                    { return nil }
func (*noopPlatformHandler) ServiceReload() error                                  { return nil }
func (*noopPlatformHandler) SystemProxyStatus() (*daemon.SystemProxyStatus, error) { return nil, nil }
func (*noopPlatformHandler) SetSystemProxyEnabled(bool) error                      { return nil }
func (*noopPlatformHandler) WriteDebugMessage(string)                              {}
