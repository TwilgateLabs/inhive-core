// url_test_config.go — honest per-server ping via a temporary side-instance.
//
// Spins a side-instance sing-box from a self-contained single-outbound config,
// runs a real HEAD probe (generate_204) THROUGH that outbound, measures the RTT,
// and tears the instance down — WITHOUT touching the main VPN box. This is how
// the Flutter app pings each server honestly even when the VPN is disconnected:
// the side-instance is independent of main-box state (same mechanism as
// BootstrapFetch / RunInstanceQuiet).
//
// Honest by construction: a dead / blocked / DPI-filtered outbound makes the
// probe fail → Error set, DelayMs 0 → the app shows "doesn't work" instead of a
// TCP connect false-positive. Works for hysteria2/QUIC, vless+reality, etc. —
// traffic goes through the outbound's own dialer, not a raw TCP probe.
//
// Failure mode mirrors BootstrapFetch: gRPC always returns a successful response;
// the caller inspects UrlTestConfigResponse.Error / .DelayMs. Panics in the
// side-instance bring-up or probe path are converted into Error via
// RecoverPanicToError.

package hcore

import (
	"context"
	"errors"
	"time"

	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/twilgate/inhive-core/v2/config"
)

const (
	urlTestConfigDefaultURL     = "https://www.gstatic.com/generate_204"
	urlTestConfigDefaultTimeout = 5 * time.Second
)

func (s *CoreService) UrlTestConfig(ctx context.Context, in *UrlTestConfigRequest) (resp *UrlTestConfigResponse, err error) {
	defer config.RecoverPanicToError("CoreService.UrlTestConfig", func(e error) {
		resp = &UrlTestConfigResponse{Error: e.Error()}
		err = nil // soft error — gRPC succeeds, payload carries the failure
	})

	if in.ConfigJson == "" {
		return &UrlTestConfigResponse{Error: "empty config_json"}, nil
	}

	url := in.Url
	if url == "" {
		url = urlTestConfigDefaultURL
	}
	timeout := time.Duration(in.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = urlTestConfigDefaultTimeout
	}

	// UnmarshalJSONContext requires a context with registered outbound/inbound/
	// endpoint registries — the bare gRPC ctx must be enriched first.
	ctx = include.Context(ctx)

	var opts option.Options
	if jsonErr := opts.UnmarshalJSONContext(ctx, []byte(in.ConfigJson)); jsonErr != nil {
		return &UrlTestConfigResponse{Error: "parse config: " + jsonErr.Error()}, nil
	}

	if len(opts.Outbounds) == 0 {
		return &UrlTestConfigResponse{Error: "no outbounds in config"}, nil
	}
	// Probe through the real EXIT outbound — NOT a group, a special outbound, or
	// the side-instance's SOCKS5 default route. The app's buildSingboxConfig puts
	// a "select" selector at outbounds[0] (members [exit, direct]), then the exit
	// outbound, then any transport detours (utproto/shadowtls). Probing the
	// selector or routing via the SOCKS5 default fails with EOF for chained
	// transports (e.g. utproto = a VLESS whose detour is a FakeTLS helper).
	// Dialing the first real proxy outbound (the exit) drives the whole detour
	// chain, so the verdict reflects real end-to-end health. Skip only GROUP
	// outbounds (selector/urltest/loadbalance) — in a ping config the exit always
	// precedes the trailing direct/block, so the first non-group is the exit.
	skipTypes := map[string]bool{"selector": true, "urltest": true, "loadbalance": true}
	var mainTag string
	for _, ob := range opts.Outbounds {
		if !skipTypes[ob.Type] {
			mainTag = ob.Tag
			break
		}
	}
	if mainTag == "" {
		return &UrlTestConfigResponse{Error: "no exit outbound in config"}, nil
	}

	// Side-instance: TUN / system-proxy / clash-api all forced off (RunInstanceQuiet).
	// The 250ms settle delay lives inside RunInstanceQuiet — BEFORE the probe — so
	// the measured delay is the genuine RTT, not inflated by instance bring-up.
	inst, instErr := RunInstanceQuiet(ctx, nil, &opts)
	if instErr != nil {
		return &UrlTestConfigResponse{Error: "run instance: " + instErr.Error()}, nil
	}
	defer inst.Close()

	b := inst.Box()
	if b == nil {
		return &UrlTestConfigResponse{Error: "side-instance not ready"}, nil
	}
	detour, ok := b.Outbound().Outbound(mainTag)
	if !ok {
		return &UrlTestConfigResponse{Error: "main outbound not found: " + mainTag}, nil
	}

	// urltest.URLTest does a real HTTP HEAD to the probe URL THROUGH the outbound's
	// own dialer (TCP-over-QUIC for hy2, the detour chain for utproto, etc.) and
	// requires the response — dead/blocked → error, no false positive.
	//
	// Best-of-N on the SAME warm side-instance (2026-06-26 ping-flake fix). The old
	// single shot declared a server dead on ANY first-attempt blip — a cold DNS
	// answer, one dropped SYN, a Reality/uTLS/WS handshake that raced the 250ms
	// settle. That is why the same config pinged 3× showed "dead" then alive on the
	// 4th: each tap measured a fresh cold path. Now we retry on the already-running
	// instance — attempt 1 gets the big slice for the cold handshake, attempts 2-3
	// ride warm OS DNS/route state and resolve fast. First success wins; only if ALL
	// attempts fail do we report a real tested-dead verdict. Total stays within the
	// caller's `timeout` budget (default 5s, under the app's 7s gRPC guard).
	testCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lastErr error
	for _, attemptTimeout := range splitProbeBudget(timeout) {
		if testCtx.Err() != nil {
			break // overall budget exhausted
		}
		attemptCtx, attemptCancel := context.WithTimeout(testCtx, attemptTimeout)
		delay, terr := urltest.URLTest(attemptCtx, url, detour)
		attemptCancel()
		if terr == nil && delay > 0 {
			return &UrlTestConfigResponse{DelayMs: int32(delay)}, nil
		}
		if terr != nil {
			lastErr = terr
			continue
		}
		lastErr = errors.New("zero delay") // terr==nil but delay==0 — soft fail, keep trying
	}
	if lastErr != nil {
		return &UrlTestConfigResponse{Error: lastErr.Error()}, nil
	}
	return &UrlTestConfigResponse{Error: "zero delay"}, nil
}

// splitProbeBudget divides the probe budget across best-of-N attempts. The first
// attempt gets the largest slice (it pays the cold DNS+TCP+TLS+WS handshake); the
// rest are smaller because they ride warm OS state and should resolve quickly.
// 60% / 20% / 20% — three shots inside one budget (5s → 3s, 1s, 1s).
func splitProbeBudget(total time.Duration) []time.Duration {
	if total <= 0 {
		total = urlTestConfigDefaultTimeout
	}
	first := total * 3 / 5
	rest := (total - first) / 2
	if rest <= 0 {
		return []time.Duration{total}
	}
	return []time.Duration{first, rest, rest}
}
