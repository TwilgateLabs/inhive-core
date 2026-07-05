package hcore

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// TestRunInstanceCore_BringUpDeadline validates Fix B (RC-4): a bring-up that
// exceeds its deadline must fail fast with an error (never hang forever, never
// panic) so a wedged side-instance can't pile up. We force the deadline by
// passing a parent context whose deadline is already in the past — context
// .WithTimeout takes the earlier of {parent deadline, bringUpBudget}, so the
// derived bringUpCtx is born expired and runInstanceCore must take its timeout
// branch immediately regardless of how fast the real bring-up would be.
func TestRunInstanceCore_BringUpDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	cfg := &option.Options{}

	start := time.Now()
	inst, err := runInstanceCore(ctx, nil, cfg)
	elapsed := time.Since(start)

	if err == nil {
		if inst != nil {
			_ = inst.Close()
		}
		t.Fatalf("expected bring-up deadline error, got nil (inst=%v)", inst)
	}
	if inst != nil {
		_ = inst.Close()
		t.Fatalf("on deadline the instance handle must be nil (no leak handed to caller), got %v", inst)
	}
	// Must return promptly — the whole point is that a wedged bring-up does NOT
	// block. Generous ceiling so a slow CI box doesn't flake.
	if elapsed > bringUpBudget {
		t.Fatalf("deadline path took %v, longer than bringUpBudget %v — did not fail fast", elapsed, bringUpBudget)
	}
	t.Logf("bring-up deadline correctly errored in %v: %v", elapsed, err)
}

// TestUrlTestConfig_BringUpDeadlineClassified validates that a bring-up timeout
// on the honest-ping path is classified as OUR failure (BringUpFailed=true), not
// a dead-server verdict — the app must show blank, never a red ×. We pass an
// already-expired context so RunInstanceQuiet times out during bring-up.
func TestUrlTestConfig_BringUpDeadlineClassified(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	cfg := `{"outbounds":[{"type":"direct","tag":"t"}]}`
	resp, err := (&CoreService{}).UrlTestConfig(ctx, &UrlTestConfigRequest{
		ConfigJson: cfg,
		TimeoutMs:  3000,
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp.Error == "" {
		t.Fatalf("bring-up timeout should surface an error")
	}
	if !resp.BringUpFailed {
		t.Fatalf("bring-up timeout is OUR failure — must be classified bring-up (blank, not red ×), got probe-failed: %s", resp.Error)
	}
	if resp.DelayMs != 0 {
		t.Fatalf("bring-up failure must report 0 delay, got %d", resp.DelayMs)
	}
	t.Logf("bring-up timeout correctly classified: %s", resp.Error)
}
