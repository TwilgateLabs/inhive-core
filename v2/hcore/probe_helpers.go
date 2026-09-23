// probe_helpers.go — the probe primitives shared by the honest per-server ping
// (url_test_config.go) and the side-instance code (independent_instance.go).
//
// Moved verbatim out of warm_probe.go on 2026-09-23 when the warm probe pool
// (UrlTestConfigWarm / ReleaseWarmProbe) was deleted — the pool had no client
// since July, but these helpers are on the live cold-probe path. Behaviour is
// unchanged; tests live in probe_helpers_test.go.
package hcore

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/twilgate/inhive-core/v2/config"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/ntp"
)

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
				MinVersion: tls.VersionTLS12,
				// Match urltest.URLTest's TLS defaults so we behave identically on a
				// device with a skewed clock or a custom root pool: NTP-corrected time
				// for cert validity, and the box's RootCAs from context. Without Time,
				// a phone whose wall clock is off fails cert validation → false-dead.
				Time:    ntp.TimeFuncFromContext(ctx),
				RootCAs: adapter.RootPoolFromContext(ctx),
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

// probeThroughDetourGuarded races probeThroughDetour against ctx. Нужна потому,
// что не весь тракт дайла контекст-отменяем: платформенные резолверы (getaddrinfo
// на darwin/windows, DnsResolver на Android) могут блокировать dial дольше любого
// бюджета — тогда handler переживал Dart-дедлайн (timeoutMs+9000), gRPC-вызов
// умирал на стороне приложения и юзер видел ПУСТОТУ вместо вердикта. Гонка
// гарантирует ответ строго в бюджете: залипшая попытка бросается (goroutine
// дорабатывает в фоне и гасится recover'ом), а истёкший ctx классифицируется
// выше как честный × — «на этой сети сейчас сервер не отвечает за бюджет» верно
// и для боевого коннекта, проба = боевой конфиг.
func probeThroughDetourGuarded(ctx context.Context, link string, detour N.Dialer, expectedStatus int) (uint16, error) {
	type probeResult struct {
		delay uint16
		err   error
	}
	ch := make(chan probeResult, 1)
	go func() {
		defer config.RecoverPanicToError("probeThroughDetour", func(e error) {
			ch <- probeResult{0, e}
		})
		delay, err := probeThroughDetour(ctx, link, detour, expectedStatus)
		ch <- probeResult{delay, err}
	}()
	select {
	case r := <-ch:
		return r.delay, r.err
	case <-ctx.Done():
		return 0, fmt.Errorf("probe budget exhausted: %w", ctx.Err())
	}
}

// readyChecker — эндпоинты wireguard/awg/warp репортят готовность туннеля
// (protocol/wireguard/endpoint.go IsReady). Обычные outbounds интерфейс не
// реализуют — для них waitDetourReady no-op.
type readyChecker interface{ IsReady() bool }

// waitDetourReady ждёт готовности endpoint-исхода перед пробой (максимум max,
// с ранним выходом по ctx). WG-handshake стартует асинхронно после старта бокса;
// дайл до готовности молча теряет пакеты → false-× холодного эндпоинта. Не
// дождались — не приговор: проба пойдёт и вынесет вердикт по своему бюджету.
func waitDetourReady(ctx context.Context, detour any, max time.Duration) {
	rc, ok := detour.(readyChecker)
	if !ok || rc.IsReady() {
		return
	}
	deadline := time.Now().Add(max)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if rc.IsReady() || time.Now().After(deadline) {
				return
			}
		}
	}
}

// isDeterministicBringUpError распознаёт КОНФИГ-УРОВНЕВЫЙ детерминированный
// провал bring-up: тот же конфиг идентично упадёт и при боевом подключении,
// поэтому «не смогли протестировать» (blank) было бы враньём — приложение мапит
// такой bring_up_failed+config_rejected в честный ×. Транзиентные корни (bind-
// гонка, bring-up timeout, паника) сюда НЕ входят — они остаются blank.
// Маркеры — фразы create/initialize-стадии sing-box (box.go startOutbounds) и
// стабов removed-протоколов (include/registry.go); start-стадия («start
// outbound/…») сознательно не матчится: там уже возможен сетевой I/O.
func isDeterministicBringUpError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	for _, marker := range []string{
		"parse config:",
		"initialize outbound",
		"initialize endpoint",
		"create outbound",
		"create endpoint",
		"unknown outbound type",
		"unknown endpoint type",
		"not available in this build",
		"is deprecated",
		"plugin not found",
	} {
		if strings.Contains(msg, marker) {
			return true
		}
	}
	return false
}

// isProbeDNSFailure reports whether a probe error is a failure to RESOLVE the
// probe hostname (gstatic) rather than a failure to connect/handshake through the
// outbound. The former is OUR inability to test (blank), the latter an honest
// tested-dead verdict (×). sing-box wraps lookup errors as `lookup <domain>: ...`
// (dns/router.go: E.Cause(err, "lookup ", domain)); Go's own resolver surfaces
// *net.DNSError. On the raw probe path (app's multi-DoH fan) this should be rare,
// but classifying it honestly keeps the invariant "× only ever means proven dead".
func isProbeDNSFailure(err error, probeHost string) bool {
	if err == nil || probeHost == "" {
		return false
	}
	probeHost = strings.TrimSuffix(probeHost, ".")
	// Blank ONLY when the PROBE TARGET (gstatic) itself failed to resolve — that is
	// OUR inability to test, not a verdict on the server. A failure to resolve the
	// SERVER's OWN address (e.g. a grpc backend on a domain that doesn't resolve /
	// resolves too slowly on the operator DNS) means the server is unreachable for the
	// user too → honest tested-dead × , NEVER blank. The old code matched ANY
	// "lookup ..." error and so mis-blanked every domain-server backend whose address
	// wouldn't resolve — that is why grpc/domain nodes showed empty instead of ×.
	// (InHive 2026-07-12)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return strings.TrimSuffix(dnsErr.Name, ".") == probeHost
	}
	msg := err.Error()
	return strings.Contains(msg, "lookup "+probeHost)
}

// probeURLHost returns the hostname of the probe URL (e.g. www.gstatic.com), used to
// tell a probe-TARGET DNS failure (blank) apart from a SERVER-address one (×).
func probeURLHost(link string) string {
	if link == "" {
		link = urlTestConfigDefaultURL
	}
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	return u.Hostname()
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
