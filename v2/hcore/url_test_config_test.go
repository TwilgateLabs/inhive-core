package hcore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// TestUrlTestConfig_Direct validates the full honest-ping plumbing end-to-end:
// config parse → side-instance bring-up → real HEAD probe through the outbound →
// delay measurement. Uses a `direct` outbound so the probe reaches the real
// generate_204 without needing a proxy server / credentials. Requires network.
func TestUrlTestConfig_Direct(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	// DNS block required now that the ping path is RAW (RunInstanceRaw): the legacy
	// translator that used to inject a working DNS is gone, so a bare config would
	// fall back to the system resolver. Real app ping configs carry the multi-DoH
	// directDns fan; mirror it with a single direct DoH-over-IP so `direct` resolves
	// gstatic. (Matches testProbeDNS in warm_probe_test.go.)
	cfg := `{"dns":{"servers":[{"tag":"dns-direct","type":"https","server":"1.1.1.1","detour":"direct"}],"final":"dns-direct"},` +
		`"outbounds":[{"type":"direct","tag":"t"},{"type":"direct","tag":"direct"}]}`
	resp, err := (&CoreService{}).UrlTestConfig(context.Background(), &UrlTestConfigRequest{
		ConfigJson: cfg,
		Url:        "", // → default https://www.gstatic.com/generate_204
		TimeoutMs:  8000,
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("direct probe should succeed, got error: %s", resp.Error)
	}
	if resp.DelayMs <= 0 {
		t.Fatalf("expected positive delay, got %d", resp.DelayMs)
	}
	t.Logf("direct outbound delay: %d ms", resp.DelayMs)
}

// TestUrlTestConfig_Dead validates the honest dead verdict: a vless outbound to
// an unroutable address must fail the probe → Error set, DelayMs 0 (the app maps
// this to kPingDeadMs / red ×). No false-positive.
func TestUrlTestConfig_Dead(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	cfg := `{"outbounds":[{"type":"vless","tag":"t","server":"10.255.255.1","server_port":1,"uuid":"00000000-0000-0000-0000-000000000000"}]}`
	resp, err := (&CoreService{}).UrlTestConfig(context.Background(), &UrlTestConfigRequest{
		ConfigJson: cfg,
		TimeoutMs:  3000,
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp.Error == "" {
		t.Fatalf("dead server should report an error, got delay=%d", resp.DelayMs)
	}
	if resp.DelayMs != 0 {
		t.Fatalf("dead server should report 0 delay, got %d", resp.DelayMs)
	}
	// The instance came up and the probe itself failed → this is a tested-dead
	// verdict, NOT a bring-up failure. Must stay a red ×, never blank.
	if resp.BringUpFailed {
		t.Fatalf("probe failure must not be classified as bring-up failure: %s", resp.Error)
	}
	t.Logf("dead outbound correctly errored: %s", resp.Error)
}

// TestSplitProbeBudget guards the best-of-N budget split (2026-06-26 ping-flake
// fix): the first attempt must get the largest slice (it pays the cold
// DNS+TCP+TLS+WS handshake), every slice must be positive, and the attempts must
// never sum past the caller's budget (else they'd blow the app's 7s gRPC guard).
func TestSplitProbeBudget(t *testing.T) {
	for _, total := range []time.Duration{
		urlTestConfigDefaultTimeout, // 5s — the real default
		8 * time.Second,
		2 * time.Second,
		1 * time.Second,
	} {
		got := splitProbeBudget(total)
		if len(got) == 0 {
			t.Fatalf("splitProbeBudget(%v): no attempts", total)
		}
		var sum time.Duration
		for _, d := range got {
			if d <= 0 {
				t.Fatalf("splitProbeBudget(%v)=%v: non-positive slice %v", total, got, d)
			}
			sum += d
		}
		if sum > total {
			t.Fatalf("splitProbeBudget(%v)=%v sums to %v > budget", total, got, sum)
		}
		for _, d := range got[1:] {
			if d > got[0] {
				t.Fatalf("splitProbeBudget(%v)=%v: first slice must be the largest", total, got)
			}
		}
	}
	// Zero / negative budget must fall back to the default budget (never empty,
	// never panic, never exceed the default).
	got := splitProbeBudget(0)
	if len(got) == 0 || got[0] <= 0 {
		t.Fatalf("splitProbeBudget(0) must fall back to positive slices, got %v", got)
	}
	var sum time.Duration
	for _, d := range got {
		sum += d
	}
	if sum > urlTestConfigDefaultTimeout {
		t.Fatalf("splitProbeBudget(0)=%v exceeds default budget %v", got, urlTestConfigDefaultTimeout)
	}
}

// TestUrlTestConfig_EmptyConfig validates input guarding.
func TestUrlTestConfig_EmptyConfig(t *testing.T) {
	resp, err := (&CoreService{}).UrlTestConfig(context.Background(), &UrlTestConfigRequest{ConfigJson: ""})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp.Error == "" {
		t.Fatalf("empty config should report an error")
	}
	if !resp.BringUpFailed {
		t.Fatalf("empty config is OUR failure — must be classified bring-up, got probe-failed")
	}
}

// TestUrlTestConfig_BringUpClassification: every failure BEFORE the probe runs
// (unparseable JSON, config without any exit) must carry BringUpFailed=true so
// the app shows blank ("couldn't test") instead of a false red × ("server
// dead"). No network needed — these all fail before instance bring-up.
func TestUrlTestConfig_BringUpClassification(t *testing.T) {
	for name, cfg := range map[string]string{
		"garbage json": `{not json`,
		"no exits":     `{"outbounds":[]}`,
		"groups only":  `{"outbounds":[{"type":"selector","tag":"select","outbounds":[]}]}`,
	} {
		resp, err := (&CoreService{}).UrlTestConfig(context.Background(), &UrlTestConfigRequest{ConfigJson: cfg})
		if err != nil {
			t.Fatalf("%s: unexpected hard error: %v", name, err)
		}
		if resp.Error == "" {
			t.Fatalf("%s: expected an error", name)
		}
		if !resp.BringUpFailed {
			t.Fatalf("%s: pre-probe failure must be bring-up class, got probe-failed (%s)", name, resp.Error)
		}
	}
}

// TestProbeTag guards the exit-tag selection (2026-07-05 endpoint honest-probe):
//   - endpoint-based configs (wireguard/awg) → the endpoint tag, even though
//     outbounds[] contains a selector + direct/block (the old "first non-group
//     outbound" rule would probe `direct` → false green);
//   - outbound-based configs → first non-group outbound (iter4: skip selector);
//   - direct-only config stays probe-able (raw-uplink check);
//   - nothing usable → "".
//
// Options are built as plain structs (probeTag reads only Type/Tag), so the
// test runs without protocol build tags (with_wireguard/with_awg) — the JSON
// registry path is exercised by the network-gated tests above.
func TestProbeTag(t *testing.T) {
	cases := []struct {
		name string
		opts option.Options
		want string
	}{
		{
			name: "endpoint preferred over selector+direct+block",
			opts: option.Options{
				Outbounds: []option.Outbound{
					{Type: "selector", Tag: "select"},
					{Type: "direct", Tag: "direct"},
					{Type: "block", Tag: "block"},
				},
				Endpoints: []option.Endpoint{{Type: "wireguard", Tag: "wg"}},
			},
			want: "wg",
		},
		{
			name: "selector skipped, exit outbound picked",
			opts: option.Options{
				Outbounds: []option.Outbound{
					{Type: "selector", Tag: "select"},
					{Type: "vless", Tag: "exit"},
					{Type: "direct", Tag: "direct"},
				},
			},
			want: "exit",
		},
		{
			name: "direct-only stays probe-able",
			opts: option.Options{
				Outbounds: []option.Outbound{{Type: "direct", Tag: "t"}},
			},
			want: "t",
		},
		{
			name: "groups only → empty",
			opts: option.Options{
				Outbounds: []option.Outbound{{Type: "selector", Tag: "select"}},
			},
			want: "",
		},
		{
			name: "empty config → empty",
			opts: option.Options{},
			want: "",
		},
	}
	for _, tc := range cases {
		if got := probeTag(&tc.opts); got != tc.want {
			t.Fatalf("%s: probeTag=%q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestUrlTestConfig_ConfigRejected: детерминированные конфиг-фейлы обязаны нести
// config_rejected=true — приложение мапит их в честный × («сервер непригоден для
// этого клиента»: боевой коннект упал бы так же), а НЕ в пустоту. Транзиентные
// bring-up фейлы config_rejected нести НЕ должны (их обрабатывает stale+retry).
func TestUrlTestConfig_ConfigRejected(t *testing.T) {
	for name, cfg := range map[string]string{
		"garbage json": `{not json`,
		"no exits":     `{"outbounds":[]}`,
		// psiphon снят с регистрации (Go 1.26 TLS), но имеет стаб — парс проходит,
		// create даёт детерминированную ошибку → bring-up → config_rejected.
		"stubbed psiphon": `{"outbounds":[{"type":"psiphon","tag":"p","server":"1.2.3.4","server_port":443}]}`,
	} {
		resp, err := (&CoreService{}).UrlTestConfig(context.Background(), &UrlTestConfigRequest{ConfigJson: cfg})
		if err != nil {
			t.Fatalf("%s: unexpected hard error: %v", name, err)
		}
		if !resp.BringUpFailed {
			t.Fatalf("%s: expected bring-up class, got probe-failed (%s)", name, resp.Error)
		}
		if !resp.ConfigRejected {
			t.Fatalf("%s: deterministic config failure must carry config_rejected (err=%s)", name, resp.Error)
		}
	}
}

// TestIsDeterministicBringUpError: маркеры create/initialize-стадии — deterministic;
// транзиентные корни (timeout, bind) — нет.
func TestIsDeterministicBringUpError(t *testing.T) {
	det := []string{
		"initialize outbound[0]: psiphon outbound is not available in this build",
		"initialize endpoint[0]: bad private key",
		"parse config: unknown outbound type: psiphon",
		"create outbound: plugin not found: fancy-plugin",
		"initialize outbound[2]: WireGuard outbound is deprecated in sing-box 1.11.0",
	}
	for _, s := range det {
		if !isDeterministicBringUpError(errors.New(s)) {
			t.Fatalf("expected deterministic: %s", s)
		}
	}
	transient := []string{
		"side-instance bring-up exceeded 8s: context deadline exceeded",
		"start outbound/vless[proxy]: dial tcp 1.2.3.4:443: connection refused",
		"listen tcp 127.0.0.1:64321: bind: address already in use",
	}
	for _, s := range transient {
		if isDeterministicBringUpError(errors.New(s)) {
			t.Fatalf("expected transient: %s", s)
		}
	}
}
