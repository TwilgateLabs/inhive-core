package hcore

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// ── fakeDialer / fakeLookup ──────────────────────────────────────────────────
//
// A fakeDialer forwards every DialContext to a fixed TCP address (an httptest
// server), so probeThroughDetour drives a REAL HTTP HEAD + status check without
// leaving the machine — the whole warm-probe HTTP path runs under `-short`. It
// counts dials so we can assert warm reuse (one instance, many probes) and
// per-tag fan-out.

type fakeDialer struct {
	target   string // host:port of the local httptest server
	dialErr  error  // if set, DialContext fails (simulates a dead outbound)
	dialsPtr *int32 // optional dial counter (atomic-free; guarded by caller)
	dials    int
}

func (d *fakeDialer) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	d.dials++
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target)
}

func (d *fakeDialer) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

var _ N.Dialer = (*fakeDialer)(nil)

type fakeLookup struct {
	dialers map[string]N.Dialer
}

func (l fakeLookup) Outbound(tag string) (N.Dialer, bool) {
	d, ok := l.dialers[tag]
	return d, ok
}

var _ dialerLookup = fakeLookup{}

// ── probeThroughDetour: status enforcement (hijack guard) ────────────────────

func TestProbeThroughDetour_StatusEnforcement(t *testing.T) {
	cases := []struct {
		name           string
		serverStatus   int
		expectedStatus int
		wantOK         bool
	}{
		{"204 accepted by default", http.StatusNoContent, 0, true},
		{"200 accepted by default", http.StatusOK, 0, true},
		{"hijack 302 rejected by default", http.StatusFound, 0, false},
		{"hijack 403 rejected by default", http.StatusForbidden, 0, false},
		{"explicit 204 required, 200 rejected", http.StatusOK, http.StatusNoContent, false},
		{"explicit 200 required, 200 accepted", http.StatusOK, http.StatusOK, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.serverStatus)
			}))
			defer srv.Close()
			host := srv.Listener.Addr().String()
			d := &fakeDialer{target: host}

			delay, err := probeThroughDetour(context.Background(), "http://"+host+"/generate_204", d, tc.expectedStatus)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if delay == 0 {
					t.Fatalf("success must report non-zero delay")
				}
			} else {
				if err == nil {
					t.Fatalf("expected status rejection, got delay=%d", delay)
				}
			}
		})
	}
}

func TestProbeThroughDetour_DeadDialer(t *testing.T) {
	d := &fakeDialer{dialErr: net.ErrClosed}
	delay, err := probeThroughDetour(context.Background(), "https://example.invalid/generate_204", d, 0)
	if err == nil {
		t.Fatalf("dead dialer must error, got delay=%d", delay)
	}
	if delay != 0 {
		t.Fatalf("dead dialer must report 0 delay, got %d", delay)
	}
}

func TestProbeThroughDetour_NilDialer(t *testing.T) {
	if _, err := probeThroughDetour(context.Background(), "", nil, 0); err == nil {
		t.Fatalf("nil dialer must error")
	}
}

// ── probeAllTags: fan-out + per-tag classification + WARM REUSE ──────────────

func TestProbeAllTags_MixedVerdicts(t *testing.T) {
	// One shared httptest server = "the warm instance's reachable Internet".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	host := srv.Listener.Addr().String()

	live := &fakeDialer{target: host}          // healthy exit
	dead := &fakeDialer{dialErr: net.ErrClosed} // blocked/dead exit
	lookup := fakeLookup{dialers: map[string]N.Dialer{
		"live": live,
		"dead": dead,
	}}

	tags := []string{"live", "dead", "missing"}
	results := probeAllTags(context.Background(), lookup, tags, "http://"+host+"/generate_204", 2*time.Second, 0)

	byTag := map[string]*UrlTestWarmResult{}
	for _, r := range results {
		byTag[r.Tag] = r
	}
	if r := byTag["live"]; r == nil || r.Error != "" || r.DelayMs <= 0 {
		t.Fatalf("live tag should have a real delay, got %+v", r)
	}
	if r := byTag["dead"]; r == nil || r.Error == "" || r.DelayMs != 0 {
		t.Fatalf("dead tag should be an honest tested-dead (error, 0 delay), got %+v", r)
	}
	if r := byTag["missing"]; r == nil || r.Error == "" {
		t.Fatalf("missing tag should report outbound-not-found, got %+v", r)
	}
}

// TestProbeAllTags_WarmReuse proves the core ping-v2 property: the SAME dialer
// object services many probes across many cycles — no per-server, per-cycle cold
// rebuild. (In production the "dialer" is a warm outbound inside the persistent
// side-instance; here the fakeDialer stands in and we count how many times it is
// driven.)
func TestProbeAllTags_WarmReuse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	host := srv.Listener.Addr().String()

	live := &fakeDialer{target: host}
	lookup := fakeLookup{dialers: map[string]N.Dialer{"live": live}}

	const cycles = 3
	for c := 0; c < cycles; c++ {
		results := probeAllTags(context.Background(), lookup, []string{"live"}, "http://"+host+"/generate_204", 2*time.Second, 0)
		if len(results) != 1 || results[0].Error != "" || results[0].DelayMs <= 0 {
			t.Fatalf("cycle %d: expected one healthy result, got %+v", c, results)
		}
	}
	// Every cycle drove the SAME dialer object — that IS the reuse. A healthy
	// best-of-N stops at the first success, so exactly `cycles` dials.
	if live.dials != cycles {
		t.Fatalf("warm reuse: expected %d dials on the shared dialer, got %d", cycles, live.dials)
	}
}

// ── probeableExitTags ────────────────────────────────────────────────────────

func TestProbeableExitTags(t *testing.T) {
	cases := []struct {
		name string
		opts option.Options
		want []string
	}{
		{
			name: "multi-server: selector + exits + direct/block",
			opts: option.Options{
				Outbounds: []option.Outbound{
					{Type: "selector", Tag: "select"},
					{Type: "vless", Tag: "nl"},
					{Type: "trojan", Tag: "de"},
					{Type: "vless", Tag: "ru"},
					{Type: "direct", Tag: "direct"},
					{Type: "block", Tag: "block"},
				},
			},
			want: []string{"nl", "de", "ru"},
		},
		{
			name: "endpoints (wireguard/awg) enumerated first",
			opts: option.Options{
				Outbounds: []option.Outbound{
					{Type: "selector", Tag: "select"},
					{Type: "vless", Tag: "nl"},
					{Type: "direct", Tag: "direct"},
				},
				Endpoints: []option.Endpoint{
					{Type: "wireguard", Tag: "wg1"},
					{Type: "wireguard", Tag: "wg2"},
				},
			},
			want: []string{"wg1", "wg2", "nl"},
		},
		{
			name: "groups + direct/block only → empty",
			opts: option.Options{
				Outbounds: []option.Outbound{
					{Type: "selector", Tag: "select"},
					{Type: "urltest", Tag: "auto"},
					{Type: "direct", Tag: "direct"},
					{Type: "block", Tag: "block"},
				},
			},
			want: nil,
		},
		{
			name: "empty config → empty",
			opts: option.Options{},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := probeableExitTags(&tc.opts)
			if len(got) != len(tc.want) {
				t.Fatalf("probeableExitTags=%v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("probeableExitTags=%v, want %v", got, tc.want)
				}
			}
		})
	}
}

// ── statusOK / probeHostPort / shortHash ─────────────────────────────────────

func TestStatusOK(t *testing.T) {
	cases := []struct {
		code, expected int
		want           bool
	}{
		{204, 0, true},
		{200, 0, true},
		{302, 0, false},
		{403, 0, false},
		{204, 204, true},
		{200, 204, false},
		{200, 200, true},
	}
	for _, tc := range cases {
		if got := statusOK(tc.code, tc.expected); got != tc.want {
			t.Fatalf("statusOK(%d,%d)=%v want %v", tc.code, tc.expected, got, tc.want)
		}
	}
}

func TestProbeHostPort(t *testing.T) {
	cases := []struct {
		link string
		want string
	}{
		{"https://www.gstatic.com/generate_204", "www.gstatic.com:443"},
		{"http://cp.cloudflare.com", "cp.cloudflare.com:80"},
		{"https://example.com:8443/x", "example.com:8443"},
	}
	for _, tc := range cases {
		got, err := probeHostPort(tc.link)
		if err != nil {
			t.Fatalf("probeHostPort(%q): %v", tc.link, err)
		}
		if got.String() != tc.want {
			t.Fatalf("probeHostPort(%q)=%q want %q", tc.link, got.String(), tc.want)
		}
	}
}

func TestShortHash(t *testing.T) {
	a := shortHash("config-A")
	b := shortHash("config-B")
	if a == b {
		t.Fatalf("distinct configs must hash differently")
	}
	if a != shortHash("config-A") {
		t.Fatalf("hash must be stable for the same input")
	}
	if len(a) != 16 {
		t.Fatalf("expected 16 hex chars, got %d (%q)", len(a), a)
	}
}

// ── registry lifecycle: reuse + release + idle reap (no network) ─────────────
//
// These exercise the registry bookkeeping with a stubbed instance so they run
// under `-short`. We inject a warmProbeEntry directly to avoid a real bring-up.

func TestReleaseWarmInstance(t *testing.T) {
	resetWarmRegistry(t)
	warmProbeRegistry.mu.Lock()
	warmProbeRegistry.instances["k1"] = &warmProbeEntry{key: "k1"}
	warmProbeRegistry.instances["k2"] = &warmProbeEntry{key: "k2"}
	warmProbeRegistry.mu.Unlock()

	releaseWarmInstance("k1")
	if warmRegistryLen() != 1 {
		t.Fatalf("release k1 should leave 1 entry, got %d", warmRegistryLen())
	}
	releaseWarmInstance("") // flush all
	if warmRegistryLen() != 0 {
		t.Fatalf("release-all should empty the registry, got %d", warmRegistryLen())
	}
	releaseWarmInstance("nonexistent") // must be a no-op, no panic
}

func TestReapIdleWarmInstances(t *testing.T) {
	resetWarmRegistry(t)
	stale := &warmProbeEntry{key: "stale"}
	stale.lastUsed.Store(time.Now().Add(-2 * warmProbeIdleTTL).UnixNano())
	fresh := &warmProbeEntry{key: "fresh"}
	fresh.touch()
	warmProbeRegistry.mu.Lock()
	warmProbeRegistry.instances["stale"] = stale
	warmProbeRegistry.instances["fresh"] = fresh
	warmProbeRegistry.mu.Unlock()

	reapIdleWarmInstances()

	if warmRegistryLen() != 1 {
		t.Fatalf("reaper should drop only the stale entry, left %d", warmRegistryLen())
	}
	warmProbeRegistry.mu.Lock()
	_, freshStillThere := warmProbeRegistry.instances["fresh"]
	_, staleGone := warmProbeRegistry.instances["stale"]
	warmProbeRegistry.mu.Unlock()
	if !freshStillThere || staleGone {
		t.Fatalf("reaper reaped the wrong entry")
	}
}

func warmRegistryLen() int {
	warmProbeRegistry.mu.Lock()
	defer warmProbeRegistry.mu.Unlock()
	return len(warmProbeRegistry.instances)
}

// resetWarmRegistry clears the registry so a test starts clean. Entries here have
// nil inst (stubs), so no box is closed.
func resetWarmRegistry(t *testing.T) {
	t.Helper()
	warmProbeRegistry.mu.Lock()
	warmProbeRegistry.instances = make(map[string]*warmProbeEntry)
	warmProbeRegistry.mu.Unlock()
}

// ── network-gated end-to-end (real warm side-instance) ───────────────────────

// TestUrlTestConfigWarm_RealWarmReuse brings up ONE real warm side-instance from a
// direct-outbound config, probes it twice under the SAME instance_key, and asserts
// the second call REUSED the instance (registry has exactly one entry, not two)
// and both probes measured a real delay to generate_204. Then ReleaseWarmProbe
// tears it down. Requires network — skipped under -short.
func TestUrlTestConfigWarm_RealWarmReuse(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	resetWarmRegistry(t)
	svc := &CoreService{}
	key := "test-warm-reuse"
	cfg := `{"outbounds":[{"type":"direct","tag":"probe"}]}`
	defer releaseWarmInstance(key)

	req := &UrlTestConfigWarmRequest{
		ConfigJson:  cfg,
		Tags:        []string{"probe"},
		InstanceKey: key,
		TimeoutMs:   8000,
	}

	// Call 1 uses a request-scoped ctx that we CANCEL right after — this is the
	// real gRPC lifecycle. The warm box must survive it (it is built on
	// static.BaseContext, not the request ctx). If bring-up wrongly bound the box
	// to this ctx, call 2 would find a torn-down instance.
	ctx1, cancel1 := context.WithCancel(context.Background())
	resp1, err := svc.UrlTestConfigWarm(ctx1, req)
	cancel1() // simulate the gRPC request completing → request ctx dies
	if err != nil {
		t.Fatalf("call 1 hard error: %v", err)
	}
	if resp1.BringUpFailed {
		t.Fatalf("call 1 bring-up failed: %s", resp1.Error)
	}
	if len(resp1.Results) != 1 || resp1.Results[0].Error != "" || resp1.Results[0].DelayMs <= 0 {
		t.Fatalf("call 1 direct probe should succeed, got %+v", resp1.Results)
	}
	if n := warmRegistryLen(); n != 1 {
		t.Fatalf("after call 1 registry should hold exactly 1 warm instance, got %d", n)
	}

	// Small gap so call 1's request ctx cancellation would have propagated to a
	// (wrongly) bound box before call 2 probes it.
	time.Sleep(300 * time.Millisecond)

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	resp2, err := svc.UrlTestConfigWarm(ctx2, req)
	if err != nil {
		t.Fatalf("call 2 hard error: %v", err)
	}
	if len(resp2.Results) != 1 || resp2.Results[0].DelayMs <= 0 {
		t.Fatalf("call 2 (reused instance) should succeed, got %+v", resp2.Results)
	}
	// The second call must have REUSED the instance — still exactly one entry.
	if n := warmRegistryLen(); n != 1 {
		t.Fatalf("reuse expected: registry should still hold 1 instance, got %d", n)
	}
	t.Logf("warm reuse OK: call1=%dms call2=%dms (same instance)", resp1.Results[0].DelayMs, resp2.Results[0].DelayMs)

	// Explicit release empties the registry.
	if _, err := svc.ReleaseWarmProbe(context.Background(), &ReleaseWarmProbeRequest{InstanceKey: key}); err != nil {
		t.Fatalf("ReleaseWarmProbe error: %v", err)
	}
	if n := warmRegistryLen(); n != 0 {
		t.Fatalf("after release registry should be empty, got %d", n)
	}
}

// TestUrlTestConfigWarm_DeadTagHonest: a warm instance holding one live (direct)
// and one dead (unroutable vless) outbound must report the live tag with a real
// delay AND the dead tag as a tested-dead × (error, 0 delay) — with BringUpFailed
// false (the instance came up; only one outbound is dead). Requires network.
func TestUrlTestConfigWarm_DeadTagHonest(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	resetWarmRegistry(t)
	svc := &CoreService{}
	key := "test-warm-dead"
	cfg := `{"outbounds":[` +
		`{"type":"direct","tag":"live"},` +
		`{"type":"vless","tag":"dead","server":"10.255.255.1","server_port":1,"uuid":"00000000-0000-0000-0000-000000000000"}` +
		`]}`
	defer releaseWarmInstance(key)

	resp, err := svc.UrlTestConfigWarm(context.Background(), &UrlTestConfigWarmRequest{
		ConfigJson:  cfg,
		Tags:        []string{"live", "dead"},
		InstanceKey: key,
		TimeoutMs:   4000,
	})
	if err != nil {
		t.Fatalf("hard error: %v", err)
	}
	if resp.BringUpFailed {
		t.Fatalf("instance came up — must not be bring-up failure: %s", resp.Error)
	}
	byTag := map[string]*UrlTestWarmResult{}
	for _, r := range resp.Results {
		byTag[r.Tag] = r
	}
	if r := byTag["live"]; r == nil || r.Error != "" || r.DelayMs <= 0 {
		t.Fatalf("live tag should have real delay, got %+v", r)
	}
	if r := byTag["dead"]; r == nil || r.Error == "" || r.DelayMs != 0 {
		t.Fatalf("dead tag should be honest tested-dead (error, 0 delay), got %+v", r)
	}
	t.Logf("honest mixed verdict OK: live=%dms dead=%q", byTag["live"].DelayMs, byTag["dead"].Error)
}

// TestUrlTestConfigWarm_BringUpFailure: an unparseable config must classify as
// BringUpFailed (OUR side), never a per-tag dead verdict. No network needed.
func TestUrlTestConfigWarm_BringUpFailure(t *testing.T) {
	resetWarmRegistry(t)
	svc := &CoreService{}
	for name, cfg := range map[string]string{
		"garbage json": `{not json`,
		"no exits":     `{"outbounds":[]}`,
		"empty":        ``,
	} {
		resp, err := svc.UrlTestConfigWarm(context.Background(), &UrlTestConfigWarmRequest{
			ConfigJson:  cfg,
			InstanceKey: "bringup-" + name,
		})
		if err != nil {
			t.Fatalf("%s: unexpected hard error: %v", name, err)
		}
		if !resp.BringUpFailed {
			t.Fatalf("%s: pre-probe failure must be bring-up class, got %+v", name, resp)
		}
		if len(resp.Results) != 0 {
			t.Fatalf("%s: bring-up failure must carry no per-tag results, got %+v", name, resp.Results)
		}
	}
}
