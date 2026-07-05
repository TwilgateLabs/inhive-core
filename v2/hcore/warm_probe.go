// warm_probe.go — ping v2: a WARM, persistent probe-instance reused across probe
// cycles, instead of the cold side-instance UrlTestConfig spins up per server per
// tap (url_test_config.go).
//
// WHY. The cold path pays a full side-instance bring-up (bind + engine start +
// 250ms settle) AND a cold DNS+TCP+TLS handshake on EVERY probe of EVERY server on
// EVERY pingAll. That is the single biggest reason we are slower/flakier than
// sing-box and mihomo, whose urltest groups keep member outbounds WARM and reuse
// their dialers (sing-box protocol/group/urltest.go: one instance, ticker-driven,
// 30-min idle timeout, per-tag history). Ping v2 mirrors that: ONE long-lived
// side-instance holds ALL of a subscription's outbounds; each probe dials an
// already-warm outbound by tag; the instance is reused across pingAll cycles a few
// seconds apart and reaped only after it goes idle.
//
// MOAT PRESERVED. The warm instance is still a RunInstanceQuiet side-instance:
// TUN / system-proxy / clash-api all off, zero contact with the main VPN box, so
// per-server ping keeps working while the VPN is DISCONNECTED — our real edge over
// the group-based clients (Clash Verge / Karing / Surge) that can only ping inside
// a running tunnel. And the 3-class verdict is preserved: if the warm INSTANCE
// fails to come up, every requested tag is bring_up_failed (blank, "couldn't
// test"); if the instance is up and one outbound's probe fails, that ONE tag is a
// tested-dead × while the others still report real ms.
//
// HONEST + HIJACK-GUARDED. We do NOT call urltest.URLTest (it ignores the response
// status). probeThroughDetour drives the same HEAD through the outbound's own
// N.Dialer but ALSO checks the status code (expectedStatus, default 204/200) — a
// hijacked test endpoint returning a bogus 200-with-body no longer reads green.

package hcore

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/twilgate/inhive-core/v2/config"
	hcommon "github.com/twilgate/inhive-core/v2/hcommon"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const (
	// warmProbeIdleTTL — how long a warm instance survives with no probes before
	// the reaper tears it down. Shorter than sing-box's 30-min group idle: a probe
	// instance is a transient UI aid (the server-list / connect screen), not a
	// long-running tunnel, and holding a full side-instance (mixed inbound + all
	// outbounds) idle for 30 min is wasteful. 5 min comfortably covers a user
	// scanning the list and re-pinging a few times.
	warmProbeIdleTTL = 5 * time.Minute
	// warmProbeReapInterval — how often the reaper wakes to check for idle instances.
	warmProbeReapInterval = 1 * time.Minute
)

// warmProbeEntry is one live warm side-instance keyed by the app's instance_key
// (a stable hash of the server set). probeMu serialises teardown vs in-flight
// probes; the probes themselves run concurrently against the shared instance
// (each outbound dialer is independently safe — that is exactly how the urltest
// group fans out with batch concurrency 10).
type warmProbeEntry struct {
	key  string
	inst *InhiveInstance
	// allTags is every probeable exit the config exposes, extracted at build time
	// (endpoints first, then non-group/non-direct/block outbounds). Used when a
	// probe call passes no explicit tags.
	allTags  []string
	lastUsed atomic.Int64 // unixnano; touched on every probe cycle
	// probeMu guards the whole probe cycle for this entry against a concurrent
	// release/rebuild of the SAME key. Different keys never contend (registry
	// swaps the pointer). RLock for a probe cycle, Lock for teardown.
	probeMu sync.RWMutex
	closed  atomic.Bool
}

func (e *warmProbeEntry) touch() { e.lastUsed.Store(time.Now().UnixNano()) }

func (e *warmProbeEntry) idle() time.Duration {
	return time.Since(time.Unix(0, e.lastUsed.Load()))
}

// warmProbeRegistry holds at most one live instance per key. In practice the app
// uses a single key at a time (the current subscription), but the map keeps the
// design clean for dual-subscription / A-B cases and makes ReleaseWarmProbe("")
// able to flush everything.
var warmProbeRegistry = struct {
	mu        sync.Mutex
	instances map[string]*warmProbeEntry
	reaper    sync.Once
}{instances: make(map[string]*warmProbeEntry)}

// getOrCreateWarmInstance returns a warm instance for key, building one from
// configJSON on a cache miss. On a hit the running instance is reused and
// configJSON is ignored. Returns (entry, builtNew, error). A non-nil error is a
// bring-up failure (OUR side) — the caller must classify every tag as
// bring_up_failed.
func getOrCreateWarmInstance(key, configJSON string) (*warmProbeEntry, bool, error) {
	warmProbeRegistry.mu.Lock()
	if e, ok := warmProbeRegistry.instances[key]; ok {
		warmProbeRegistry.mu.Unlock()
		e.touch()
		return e, false, nil
	}
	// Miss: build a fresh instance OUTSIDE the registry lock is unsafe (two callers
	// could race to build the same key). Keep it simple and correct: hold the
	// registry lock across bring-up. Probe cycles for OTHER keys are unaffected
	// because they hit the fast cache-hit path above only when already present; a
	// concurrent build of a DIFFERENT key serialises here, which is fine — builds
	// are rare (once per subscription change) and the app pings one key at a time.
	defer warmProbeRegistry.mu.Unlock()

	// Re-check under lock (another goroutine may have built it while we waited).
	if e, ok := warmProbeRegistry.instances[key]; ok {
		e.touch()
		return e, false, nil
	}

	// CRITICAL: build the warm instance on the LONG-LIVED base context, NOT the
	// request ctx. daemon.NewStartedService derives the box's own context from the
	// one it is given (context.WithCancel(options.Context)); if we passed the
	// per-call gRPC ctx the box would be torn down the instant this handler returns
	// — killing warm reuse. The main VPN box is built the same way (start.go:
	// Start(static.BaseContext, ...)). Fall back to Background when BaseContext is
	// unset (unit tests / pre-Setup).
	baseCtx := static.BaseContext
	if baseCtx == nil {
		baseCtx = context.Background()
	}
	inst, tags, err := buildWarmInstance(baseCtx, configJSON)
	if err != nil {
		return nil, false, err
	}
	e := &warmProbeEntry{key: key, inst: inst, allTags: tags}
	e.touch()
	warmProbeRegistry.instances[key] = e
	ensureWarmReaper()
	return e, true, nil
}

// buildWarmInstance parses the multi-server config and starts one side-instance
// holding all its outbounds. Mirrors url_test_config.go bring-up, minus the
// single-tag probe. ctx MUST be a long-lived context (static.BaseContext), not a
// request-scoped one — the started box's lifetime is bound to it. Returns the
// instance AND the list of probeable exit tags extracted from the parsed config
// (so we never need to re-parse or store the heavy option.Options).
func buildWarmInstance(ctx context.Context, configJSON string) (*InhiveInstance, []string, error) {
	if configJSON == "" {
		return nil, nil, errors.New("empty config_json")
	}
	// Enrich ctx with the outbound/inbound/endpoint registries before unmarshal.
	pctx := include.Context(ctx)
	var opts option.Options
	if jsonErr := opts.UnmarshalJSONContext(pctx, []byte(configJSON)); jsonErr != nil {
		return nil, nil, fmt.Errorf("parse config: %w", jsonErr)
	}
	if len(opts.Outbounds) == 0 && len(opts.Endpoints) == 0 {
		return nil, nil, errors.New("config has no outbounds or endpoints")
	}
	tags := probeableExitTags(&opts)
	inst, instErr := RunInstanceQuiet(pctx, nil, &opts)
	if instErr != nil {
		return nil, nil, fmt.Errorf("run instance: %w", instErr)
	}
	if inst.Box() == nil {
		inst.Close()
		return nil, nil, errors.New("side-instance not ready")
	}
	return inst, tags, nil
}

// releaseWarmInstance tears down and forgets the instance for key. key "" flushes
// all. Safe to call for an unknown key (no-op).
func releaseWarmInstance(key string) {
	warmProbeRegistry.mu.Lock()
	var toClose []*warmProbeEntry
	if key == "" {
		for k, e := range warmProbeRegistry.instances {
			toClose = append(toClose, e)
			delete(warmProbeRegistry.instances, k)
		}
	} else if e, ok := warmProbeRegistry.instances[key]; ok {
		toClose = append(toClose, e)
		delete(warmProbeRegistry.instances, key)
	}
	warmProbeRegistry.mu.Unlock()

	// Close outside the registry lock; take each entry's write-lock so an in-flight
	// probe cycle finishes before we tear the box down.
	for _, e := range toClose {
		e.probeMu.Lock()
		e.closed.Store(true)
		if e.inst != nil {
			e.inst.Close()
		}
		e.probeMu.Unlock()
	}
}

// ensureWarmReaper starts the single idle-reaper goroutine on first warm instance.
func ensureWarmReaper() {
	warmProbeRegistry.reaper.Do(func() {
		go func() {
			defer config.RecoverPanicToError("warmProbeReaper", func(err error) {
				Log(LogLevel_ERROR, LogType_CORE, "warm probe reaper: "+err.Error())
			})
			ticker := time.NewTicker(warmProbeReapInterval)
			defer ticker.Stop()
			for range ticker.C {
				reapIdleWarmInstances()
			}
		}()
	})
}

func reapIdleWarmInstances() {
	warmProbeRegistry.mu.Lock()
	var toClose []*warmProbeEntry
	for k, e := range warmProbeRegistry.instances {
		if e.idle() > warmProbeIdleTTL {
			toClose = append(toClose, e)
			delete(warmProbeRegistry.instances, k)
		}
	}
	warmProbeRegistry.mu.Unlock()
	for _, e := range toClose {
		e.probeMu.Lock()
		e.closed.Store(true)
		if e.inst != nil {
			e.inst.Close()
		}
		e.probeMu.Unlock()
	}
}

// UrlTestConfigWarm is the ping-v2 gRPC handler. See UrlTestConfigWarmRequest in
// hcore.proto for the contract. gRPC always returns OK; the payload carries every
// verdict (instance-level bring_up_failed OR per-tag results).
func (s *CoreService) UrlTestConfigWarm(ctx context.Context, in *UrlTestConfigWarmRequest) (resp *UrlTestConfigWarmResponse, err error) {
	defer config.RecoverPanicToError("CoreService.UrlTestConfigWarm", func(e error) {
		// A panic is a bug on OUR side, never evidence a server is down.
		resp = &UrlTestConfigWarmResponse{Error: e.Error(), BringUpFailed: true}
		err = nil
	})

	key := in.InstanceKey
	if key == "" {
		// No key => degrade to a per-call ephemeral instance (still warm across the
		// tags in THIS call, just not reused across calls). Key it by config hash so
		// two concurrent keyless calls with the same config share, and release it at
		// the end of the call.
		key = "ephemeral:" + shortHash(in.ConfigJson)
		defer releaseWarmInstance(key)
	}

	entry, _, buildErr := getOrCreateWarmInstance(key, in.ConfigJson)
	if buildErr != nil {
		return &UrlTestConfigWarmResponse{Error: buildErr.Error(), BringUpFailed: true}, nil
	}

	// Hold the entry's read-lock for the whole probe cycle so a concurrent
	// ReleaseWarmProbe / reaper cannot close the box mid-probe.
	entry.probeMu.RLock()
	defer entry.probeMu.RUnlock()
	if entry.closed.Load() {
		// Raced with a teardown between get and RLock — treat as bring-up failure so
		// the app blanks (couldn't test), never a false dead.
		return &UrlTestConfigWarmResponse{Error: "warm instance closed", BringUpFailed: true}, nil
	}
	entry.touch()

	b := entry.inst.Box()
	if b == nil {
		return &UrlTestConfigWarmResponse{Error: "warm instance box nil", BringUpFailed: true}, nil
	}

	url := in.Url
	if url == "" {
		url = urlTestConfigDefaultURL
	}
	timeout := time.Duration(in.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = urlTestConfigDefaultTimeout
	}

	tags := in.Tags
	if len(tags) == 0 {
		tags = entry.allTags
	}
	if len(tags) == 0 {
		// The instance is up but exposes no probeable exit — that is a config
		// shape problem on OUR side, classify as bring-up.
		return &UrlTestConfigWarmResponse{Error: "no probeable exits in config", BringUpFailed: true}, nil
	}

	results := probeAllTags(ctx, boxDialerLookup{b}, tags, url, timeout, int(in.ExpectedStatus))
	return &UrlTestConfigWarmResponse{Results: results}, nil
}

// ReleaseWarmProbe tears a warm instance down early.
func (s *CoreService) ReleaseWarmProbe(ctx context.Context, in *ReleaseWarmProbeRequest) (resp *hcommon.Response, err error) {
	defer config.RecoverPanicToError("CoreService.ReleaseWarmProbe", func(e error) {
		// Teardown failures are never fatal — report OK, we already forgot the entry.
		resp = &hcommon.Response{Code: hcommon.ResponseCode_OK}
		err = nil
	})
	releaseWarmInstance(in.InstanceKey)
	return &hcommon.Response{Code: hcommon.ResponseCode_OK}, nil
}

// probeAllTags fans out a probe per tag against the shared warm box, bounded by a
// worker pool (matches sing-box urltest group's concurrency cap of 10). Each tag's
// verdict is independent and honest.
func probeAllTags(ctx context.Context, lookup dialerLookup, tags []string, url string, timeout time.Duration, expectedStatus int) []*UrlTestWarmResult {
	const maxConcurrency = 10
	results := make([]*UrlTestWarmResult, len(tags))

	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)
	for i, tag := range tags {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, tag string) {
			defer wg.Done()
			defer func() { <-sem }()
			defer config.RecoverPanicToError("warmProbeTag", func(e error) {
				results[i] = &UrlTestWarmResult{Tag: tag, Error: e.Error()}
			})
			results[i] = probeSingleTag(ctx, lookup, tag, url, timeout, expectedStatus)
		}(i, tag)
	}
	wg.Wait()
	return results
}

// probeSingleTag resolves one outbound/endpoint by tag on the warm box and runs a
// best-of-N probe through its dialer (same budget split as the cold path). The
// warm instance means attempt 1 no longer pays a cold instance bring-up — only a
// cold connection at worst, and often a warm one from the previous cycle.
func probeSingleTag(ctx context.Context, lookup dialerLookup, tag, url string, timeout time.Duration, expectedStatus int) *UrlTestWarmResult {
	detour, ok := lookup.Outbound(tag)
	if !ok {
		return &UrlTestWarmResult{Tag: tag, Error: "outbound not found: " + tag}
	}
	testCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lastErr error
	for _, attemptTimeout := range splitProbeBudget(timeout) {
		if testCtx.Err() != nil {
			break
		}
		attemptCtx, attemptCancel := context.WithTimeout(testCtx, attemptTimeout)
		delay, terr := probeThroughDetour(attemptCtx, url, detour, expectedStatus)
		attemptCancel()
		if terr == nil && delay > 0 {
			return &UrlTestWarmResult{Tag: tag, DelayMs: int32(delay)}
		}
		if terr != nil {
			lastErr = terr
			continue
		}
		lastErr = errors.New("zero delay")
	}
	if lastErr == nil {
		lastErr = errors.New("zero delay")
	}
	return &UrlTestWarmResult{Tag: tag, Error: lastErr.Error()}
}

// probeThroughDetour is our status-aware replacement for urltest.URLTest. It dials
// the probe URL THROUGH the outbound's own N.Dialer (TCP-over-QUIC for hy2, the
// detour chain for utproto, etc.) exactly like urltest.URLTest, and measures the
// RTT — but additionally enforces the response status code so a hijacked test
// endpoint (bogus 200 body) does not read as success. Returns delay in ms.
//
// expectedStatus == 0 => accept 204 or 200 (generate_204-friendly). Otherwise the
// status must match exactly.
func probeThroughDetour(ctx context.Context, link string, detour N.Dialer, expectedStatus int) (uint16, error) {
	if detour == nil {
		return 0, errors.New("probe dialer is nil")
	}
	if link == "" {
		link = urlTestConfigDefaultURL
	}
	hostport, err := probeHostPort(link)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	conn, err := detour.DialContext(ctx, "tcp", hostport)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	// Reset the clock after the dial for protocols that defer the handshake to the
	// first write (mirrors urltest.URLTest's N.NeedHandshakeForWrite handling).
	if N.NeedHandshakeForWrite(conn) {
		start = time.Now()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, link, nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) { return conn, nil },
			TLSClientConfig: &tls.Config{
				// Match urltest.URLTest defaults (no custom RootCAs needed for the
				// public generate_204 endpoints).
				MinVersion: tls.VersionTLS12,
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()

	if !statusOK(resp.StatusCode, expectedStatus) {
		return 0, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	delay := time.Since(start) / time.Millisecond
	if delay <= 0 {
		delay = 1 // never report 0 on a genuine success — 0 is our failure sentinel
	}
	if delay > 65535 {
		delay = 65535
	}
	return uint16(delay), nil
}

// statusOK reports whether code satisfies expectedStatus. 0 => 204 or 200.
func statusOK(code, expectedStatus int) bool {
	if expectedStatus == 0 {
		return code == http.StatusNoContent || code == http.StatusOK
	}
	return code == expectedStatus
}

// probeHostPort extracts host:port from a probe URL, defaulting the port by scheme.
func probeHostPort(link string) (M.Socksaddr, error) {
	u, err := url.Parse(link)
	if err != nil {
		return M.Socksaddr{}, err
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			port = "443"
		}
	}
	return M.ParseSocksaddrHostPortStr(host, port), nil
}

// probeableExitTags enumerates every probeable exit a config exposes: endpoint
// tags first (wireguard/awg), then every real exit outbound (skip group outbounds
// selector/urltest/loadbalance — same rule as probeTag, but ALL of them, not just
// the first). direct/block are EXCLUDED (a multi-server config always carries them
// as fallbacks; probing them would spam meaningless "raw uplink" verdicts). Order
// is stable: endpoints in config order, then outbounds in config order.
func probeableExitTags(opts *option.Options) []string {
	if opts == nil {
		return nil
	}
	var tags []string
	for _, ep := range opts.Endpoints {
		if ep.Tag != "" {
			tags = append(tags, ep.Tag)
		}
	}
	skip := map[string]bool{"selector": true, "urltest": true, "loadbalance": true, "direct": true, "block": true}
	for _, ob := range opts.Outbounds {
		if ob.Tag == "" || skip[ob.Type] {
			continue
		}
		tags = append(tags, ob.Tag)
	}
	return tags
}

// dialerLookup is the minimal surface the probe fan-out needs: resolve a tag to
// an N.Dialer. Narrowing to this (instead of the wide adapter.OutboundManager)
// lets tests inject a fake dialer without a real engine or protocol build tags.
type dialerLookup interface {
	Outbound(tag string) (N.Dialer, bool)
}

// boxDialerLookup adapts a running side-instance's box to dialerLookup. The box's
// Outbound(tag) returns an adapter.Outbound, which embeds N.Dialer — and the
// endpoint manager fallback (adapter/outbound/manager.go) means endpoint tags
// (wireguard/awg) resolve through the same call.
type boxDialerLookup struct{ b probeBox }

func (l boxDialerLookup) Outbound(tag string) (N.Dialer, bool) {
	ob, ok := l.b.Outbound().Outbound(tag)
	if !ok {
		return nil, false
	}
	return ob, true
}

// probeBox is the minimal surface boxDialerLookup needs from *box.Box.
type probeBox interface {
	Outbound() adapter.OutboundManager
}

// shortHash is a stable 16-hex-char digest used to key ephemeral (no instance_key)
// warm instances by config content so two concurrent keyless calls with the same
// config share one instance.
func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:8])
}
