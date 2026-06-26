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

	// Side-instance: TUN / system-proxy / clash-api all forced off, SOCKS5 on a
	// random localhost port (RunInstanceQuiet). The 250ms settle delay lives
	// inside RunInstanceQuiet — BEFORE the measurement below — so DelayMs is the
	// genuine RTT through the outbound, not inflated by instance bring-up.
	inst, instErr := RunInstanceQuiet(ctx, nil, &opts)
	if instErr != nil {
		return &UrlTestConfigResponse{Error: "run instance: " + instErr.Error()}, nil
	}
	defer inst.Close()

	start := time.Now()
	// Real HEAD probe THROUGH the side-instance outbound (SOCKS5 → outbound →
	// url). ContentFromURL fails on non-2xx/204 or any transport error → honest
	// "doesn't work".
	if _, probeErr := inst.ContentFromURL("HEAD", url, timeout); probeErr != nil {
		return &UrlTestConfigResponse{Error: probeErr.Error()}, nil
	}
	return &UrlTestConfigResponse{DelayMs: int32(time.Since(start).Milliseconds())}, nil
}
