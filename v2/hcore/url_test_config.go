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
	// Probe through the FIRST outbound (the exit), NOT the side-instance's SOCKS5
	// default route. For chained transports (utproto = a vless with detour→utproto
	// helper) the helper is a transport layer, not an exit — routing via the
	// SOCKS5 default could pick the helper and the probe fails with EOF even when
	// the server works. Dialing the main outbound drives the whole detour chain,
	// so the verdict reflects real end-to-end health.
	mainTag := opts.Outbounds[0].Tag

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
	testCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	delay, terr := urltest.URLTest(testCtx, url, detour)
	if terr != nil {
		return &UrlTestConfigResponse{Error: terr.Error()}, nil
	}
	if delay == 0 {
		return &UrlTestConfigResponse{Error: "zero delay"}, nil
	}
	return &UrlTestConfigResponse{DelayMs: int32(delay)}, nil
}
