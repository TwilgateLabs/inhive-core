package hcore

import (
	"context"
	"testing"
	"time"
)

// TestUrlTestConfig_Direct validates the full honest-ping plumbing end-to-end:
// config parse → side-instance bring-up → real HEAD probe through the outbound →
// delay measurement. Uses a `direct` outbound so the probe reaches the real
// generate_204 without needing a proxy server / credentials. Requires network.
func TestUrlTestConfig_Direct(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	cfg := `{"outbounds":[{"type":"direct","tag":"t"}]}`
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
}
