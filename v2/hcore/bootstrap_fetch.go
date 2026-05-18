// bootstrap_fetch.go — Wave 13D Bootstrap Subscription Fetch.
//
// One-shot HTTP GET through a temporary side-instance sing-box. Used by the
// Flutter app to fetch a subscription URL through a DPI-bypass urltest carousel
// of bootstrap endpoints when the user is on a hostile carrier (Megafon /
// Beeline / MTS LTE) that would otherwise block the bare TCP connection.
//
// The temporary instance is set up by RunInstance with TUN, system proxy, clash
// API and tproxy/redirect/direct ports all forced off, leaving only a SOCKS5
// inbound on a random localhost port (see RunInstance in independent_instance.go).
// We dial that SOCKS5 with our own http.Client so we get the precise status_code
// back to the caller — InhiveInstance.ContentFromURL collapses non-2xx into a
// generic error and is shared with Ping/PingAverage/PingCloudflare, so we keep
// the dialer code local instead of widening the shared helper.
//
// Failure mode: gRPC always returns a successful response — caller inspects
// BootstrapFetchResponse.Error / .StatusCode. Panics in the side-instance bring-up
// or HTTP path are converted into Error via RecoverPanicToError, mirroring Parse.

package hcore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/twilgate/inhive-core/v2/config"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"golang.org/x/net/proxy"
)

const (
	bootstrapFetchDefaultTimeout = 30 * time.Second
	bootstrapFetchUserAgent      = "InHive-Bootstrap/1.0"
)

func (s *CoreService) BootstrapFetch(ctx context.Context, in *BootstrapFetchRequest) (resp *BootstrapFetchResponse, err error) {
	start := time.Now()
	defer config.RecoverPanicToError("CoreService.BootstrapFetch", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp = &BootstrapFetchResponse{
			Error:      e.Error(),
			DurationMs: int32(time.Since(start).Milliseconds()),
		}
		err = nil // soft error — gRPC succeeds, payload carries the failure
	})

	if in.Url == "" {
		return &BootstrapFetchResponse{
			Error:      "empty url",
			DurationMs: int32(time.Since(start).Milliseconds()),
		}, nil
	}
	if in.ConfigJson == "" {
		return &BootstrapFetchResponse{
			Error:      "empty config_json",
			DurationMs: int32(time.Since(start).Milliseconds()),
		}, nil
	}

	timeout := time.Duration(in.TimeoutMs) * time.Millisecond
	if timeout == 0 {
		timeout = bootstrapFetchDefaultTimeout
	}

	// UnmarshalJSONContext requires a context with registered outbound/inbound/endpoint
	// registries. The incoming gRPC ctx is bare — enrich it before unmarshalling.
	ctx = include.Context(ctx)

	var opts option.Options
	if jsonErr := opts.UnmarshalJSONContext(ctx, []byte(in.ConfigJson)); jsonErr != nil {
		return &BootstrapFetchResponse{
			Error:      "parse config: " + jsonErr.Error(),
			DurationMs: int32(time.Since(start).Milliseconds()),
		}, nil
	}

	// Side-instance with overrides forced by RunInstance (no TUN, no system
	// proxy, SOCKS5 on random localhost port). nil InhiveOptions => DefaultInhiveOptions.
	// Quiet variant skips the cp.cloudflare.com warm-up probe — Cloudflare is blocked
	// on RU LTE so the probe would burn 4s of the BootstrapFetch budget for nothing.
	inst, instErr := RunInstanceQuiet(ctx, nil, &opts)
	if instErr != nil {
		return &BootstrapFetchResponse{
			Error:      "run instance: " + instErr.Error(),
			DurationMs: int32(time.Since(start).Milliseconds()),
		}, nil
	}
	defer inst.Close()

	dialer, dialerErr := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", inst.ListenPort), nil, proxy.Direct)
	if dialerErr != nil {
		return &BootstrapFetchResponse{
			Error:      "socks dialer: " + dialerErr.Error(),
			DurationMs: int32(time.Since(start).Milliseconds()),
		}, nil
	}

	httpClient := &http.Client{
		Transport: &http.Transport{Dial: dialer.Dial},
		Timeout:   timeout,
	}

	httpReq, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, in.Url, nil)
	if reqErr != nil {
		return &BootstrapFetchResponse{
			Error:      "new request: " + reqErr.Error(),
			DurationMs: int32(time.Since(start).Milliseconds()),
		}, nil
	}
	httpReq.Header.Set("User-Agent", bootstrapFetchUserAgent)

	httpResp, doErr := httpClient.Do(httpReq)
	if doErr != nil {
		return &BootstrapFetchResponse{
			Error:      "http do: " + doErr.Error(),
			DurationMs: int32(time.Since(start).Milliseconds()),
		}, nil
	}
	defer httpResp.Body.Close()

	body, readErr := io.ReadAll(httpResp.Body)
	if readErr != nil {
		return &BootstrapFetchResponse{
			StatusCode: int32(httpResp.StatusCode),
			Error:      "read body: " + readErr.Error(),
			DurationMs: int32(time.Since(start).Milliseconds()),
		}, nil
	}

	return &BootstrapFetchResponse{
		Body:       body,
		StatusCode: int32(httpResp.StatusCode),
		DurationMs: int32(time.Since(start).Milliseconds()),
	}, nil
}
