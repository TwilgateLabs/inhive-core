// urltest_watcher.go — Phase 2 mode-switch health detector.
//
// Watches the existing OutboundMonitoring URL-test stream (created by
// sing-box itself) for the main outbound group, accumulates a sliding
// window of probe verdicts and emits a Mode-2 recommendation event on the
// ModeStateListener stream when the configured threshold is crossed.
//
// Scope:
//   - Detection only. Core does NOT itself perform a cross-mode switch —
//     the main app reacts to the recommendation by restarting the NE
//     Provider with a different providerConfiguration (out of scope here).
//   - Watches only Mode-1 health. Mode-2 → Mode-1 recovery currently has
//     no in-watcher trigger because Mode-1 outbounds are not probed while
//     sing-box is unloaded; the hysteresis counter is wired but never
//     advances automatically. The main app can still issue SwitchMode(1)
//     manually (e.g. on Wi-Fi reattach via NWPathMonitor). This is called
//     out as an open question in the Phase 2 brief.
package hcore

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/twilgate/inhive-core/v2/config"
)

const (
	// Sliding window size — number of recent per-outbound verdicts kept.
	// Per plan: 10 probes.
	modeWatcherWindow = 10
	// Consecutive-failures threshold to recommend Mode 2.
	modeWatcherConsecFailures = 7
	// Failure-rate threshold (fraction) over the window to recommend Mode 2.
	modeWatcherFailRate = 0.70
	// Cool-down between two recommendation emissions.
	modeWatcherDebounce = 30 * time.Second
	// Mode 1 successes required after a Mode-2 recommendation before the
	// watcher will treat the carousel as healthy again. See package doc —
	// today this only advances if the main app stays in Mode 1.
	modeWatcherRecoveryStreak = 3
)

// startModeWatcher binds a watcher to the freshly-built sing-box instance.
// Safe to call repeatedly: each invocation cancels the previous watcher
// before launching a new one (the new sing-box context invalidates the old
// monitoring subscription anyway).
//
// Called from StartService once the daemon is up. The watcher exits cleanly
// on either context cancellation: its own (from stopModeWatcher / Stop) or
// the sing-box instance's (engine shutdown).
func startModeWatcher(boxCtx context.Context, instance *InhiveInstance) {
	if instance == nil || boxCtx == nil {
		return
	}

	static.modeWatcherMu.Lock()
	if static.modeWatcherCancel != nil {
		// Previous run still alive; tear it down first.
		static.modeWatcherCancel()
	}
	ctx, cancel := context.WithCancel(boxCtx)
	static.modeWatcherCancel = cancel
	static.modeWatcherMu.Unlock()

	go func() {
		defer config.DeferPanicToError("modeWatcher", func(err error) {
			Log(LogLevel_ERROR, LogType_CORE, "modeWatcher panic: ", err.Error())
		})
		instance.runModeWatcher(ctx)
	}()
}

// stopModeWatcher cancels any active watcher. Idempotent.
func stopModeWatcher() {
	static.modeWatcherMu.Lock()
	defer static.modeWatcherMu.Unlock()
	if static.modeWatcherCancel != nil {
		static.modeWatcherCancel()
		static.modeWatcherCancel = nil
	}
}

func (h *InhiveInstance) runModeWatcher(ctx context.Context) {
	// Wait briefly for monitoring service + main group to be ready.
	monitor := h.waitMonitor(ctx)
	if monitor == nil {
		return
	}

	// Use the empty group tag — same convention as proxy_info.go which
	// receives events for the whole main carousel. Avoids duplicating the
	// "which group is primary" decision.
	events, err := monitor.SubscribeGroup("")
	if err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "modeWatcher: SubscribeGroup failed: ", err.Error())
		return
	}
	defer monitor.UnsubscribeGroup("", events)

	Log(LogLevel_DEBUG, LogType_CORE, "modeWatcher: started")

	// Sliding window stored as a ring buffer of pass/fail booleans.
	// true == failure. We only care about the most recent verdict per
	// outbound in the carousel; we squash multiple outbounds' results from
	// one cycle into a single window slot keyed by best-of-cycle.
	window := make([]bool, 0, modeWatcherWindow)
	var lastEmit time.Time
	recoveryStreak := 0

	for {
		select {
		case <-ctx.Done():
			Log(LogLevel_DEBUG, LogType_CORE, "modeWatcher: ctx done, exiting")
			return
		case _, ok := <-events:
			if !ok {
				Log(LogLevel_DEBUG, LogType_CORE, "modeWatcher: event channel closed")
				return
			}
		}

		// One sing-box urltest cycle completed for this group. Compute
		// best-of-cycle verdict: cycle is "healthy" if at least one
		// outbound came back with a usable delay.
		hist := monitor.OutboundsHistory("")
		failed := isCycleFailed(hist)

		window = appendBounded(window, failed, modeWatcherWindow)

		// Track Mode-1 recovery streak only while the main app says we're
		// in Mode 1 already; otherwise the carousel is being probed without
		// providing real-traffic feedback (the data plane is on Mode 2).
		if static.currentMode.Load() == 1 && !failed {
			recoveryStreak++
		} else if failed {
			recoveryStreak = 0
		}
		_ = recoveryStreak // referenced for future Mode 2→1 logic; see file doc.

		if !shouldRecommendModeTwo(window) {
			continue
		}
		if time.Since(lastEmit) < modeWatcherDebounce {
			continue
		}
		// Only recommend a switch when we're actually in Mode 1. If the
		// main app has already moved to Mode 2 the carousel is degraded
		// by definition (it's not in use) — sending another event would
		// just be noise.
		if static.currentMode.Load() != 1 {
			continue
		}
		lastEmit = time.Now()
		// Note we don't override active_transport here — recommendation
		// events report the *current* transport (still Mode 1) so the UI
		// can show what's being abandoned. The post-switch event from
		// SwitchMode(2) will report the new one.
		emitModeState(2, "", "")
		Log(LogLevel_WARNING, LogType_CORE,
			"modeWatcher: Mode 1 outbounds unhealthy — recommending Mode 2 switch")
	}
}

// waitMonitor blocks until the sing-box monitoring service is reachable or
// the context is cancelled. Without this the very first SubscribeGroup
// call can race the daemon's startup and return "group not found".
func (h *InhiveInstance) waitMonitor(ctx context.Context) *monitoring.OutboundMonitoring {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		if boxCtx := h.Context(); boxCtx != nil {
			if m := monitoring.Get(boxCtx); m != nil {
				return m
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-deadline.C:
			Log(LogLevel_WARNING, LogType_CORE, "modeWatcher: monitoring not ready after 10s")
			return nil
		case <-ticker.C:
		}
	}
}

// isCycleFailed returns true when no outbound in the supplied history
// produced a successful, non-cached delay. Mirrors how
// adapter.URLTestHistory.Delay encodes status (0 = cache, 65535 = timeout,
// other = real ms).
func isCycleFailed(hist map[string]*adapter.URLTestHistory) bool {
	if len(hist) == 0 {
		return false // no data yet — don't penalise startup
	}
	for _, h := range hist {
		if h == nil {
			continue
		}
		if h.IsFromCache {
			continue
		}
		// monitoring.TimeoutDelay is the canonical "this probe failed"
		// sentinel (uint16 max). We re-use the magic constant via a
		// numeric compare to avoid a cross-package import just for one
		// value.
		if h.Delay > 0 && h.Delay < 65535 {
			return false
		}
	}
	return true
}

func appendBounded(window []bool, v bool, max int) []bool {
	window = append(window, v)
	if len(window) > max {
		window = window[len(window)-max:]
	}
	return window
}

// shouldRecommendModeTwo applies the two thresholds from the plan:
//
//	7+ consecutive failures at the tail of the window, OR
//	70%+ failure rate across a fully-populated window.
func shouldRecommendModeTwo(window []bool) bool {
	if len(window) == 0 {
		return false
	}
	// Consecutive-tail check.
	consec := 0
	for i := len(window) - 1; i >= 0; i-- {
		if !window[i] {
			break
		}
		consec++
	}
	if consec >= modeWatcherConsecFailures {
		return true
	}
	// Fail-rate check (only meaningful with a full window).
	if len(window) < modeWatcherWindow {
		return false
	}
	failed := 0
	for _, f := range window {
		if f {
			failed++
		}
	}
	rate := float64(failed) / float64(len(window))
	return rate >= modeWatcherFailRate
}

// emitModeState builds and publishes a snapshot event.
//
//	modeOverride — non-zero forces the event's current_mode to that value
//	  (used for "recommend Mode 2" emissions); zero falls back to the
//	  currently-stored desired mode.
//	errMsg        — non-empty marks the event as a failure (success=false).
//	transportHint — optional override; when empty we resolve it from the
//	  live routing state (best-effort, empty if daemon is down).
func emitModeState(modeOverride int32, errMsg, transportHint string) {
	target := modeOverride
	if target == 0 {
		target = static.currentMode.Load()
	}
	transport := transportHint
	if transport == "" {
		transport = currentActiveTransport()
	}
	resp := &ModeStateResponse{
		CurrentMode:     target,
		Success:         errMsg == "",
		Error:           errMsg,
		TimestampMs:     time.Now().UnixMilli(),
		ActiveTransport: transport,
	}
	if static.modeStateObserver != nil {
		static.modeStateObserver.Publish(resp)
	}
}

// currentActiveTransport snapshots the routing-level active outbound for
// the main selector group. Best-effort — empty string when the daemon
// isn't up. Kept here (not in proxy_info.go) to limit blast radius of the
// new feature.
func currentActiveTransport() string {
	box := static.Box()
	if box == nil {
		return ""
	}
	currentOutbound, ok := box.Outbound().Outbound(config.OutboundSelectTag)
	if !ok {
		return ""
	}
	group, isGroup := currentOutbound.(adapter.OutboundGroup)
	if !isGroup {
		return ""
	}
	tag := group.Now()
	// Drill one level deeper if the selected entry is itself a group (e.g.
	// urltest-of-urltests). Mirrors readStatus() in commands.go.
	if inner, ok := box.Outbound().Outbound(tag); ok {
		if innerGroup, ok := inner.(adapter.OutboundGroup); ok {
			if now := innerGroup.Now(); now != "" {
				return TrimTagName(now)
			}
		}
	}
	return TrimTagName(tag)
}
