// speed_test.go — gRPC handler для измерения throughput через outbound.
//
// Раньше Dart-side делал HTTP request через mixed inbound (127.0.0.1:12354).
// На iOS это архитектурно сломано: main app и core живут в разных процессах
// (NEPacketTunnel), и прокси-канал app↔core через mixed proxy не работает
// (либо port не listen'ит в TUN-only mode, либо routing loop через TUN).
//
// Решение: переносим speed test в core (как UrlTest для ping). Один gRPC
// call, core сам делает HTTP request через outbound.DialContext, измеряет
// время и возвращает kbps. Работает одинаково на всех платформах.

package hcore

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/ntp"
	"github.com/twilgate/inhive-core/v2/config"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
)

const (
	// Дефолтные параметры если в request не заданы.
	defaultTestBytes  int64 = 2_000_000 // 2 MB
	defaultTimeoutSec int32 = 20
	speedTestHost           = "speed.cloudflare.com"
	speedTestPort           = "443"
)

// SpeedTest — gRPC handler. Делает download (или upload) через outbound,
// возвращает скорость в KB/s.
func (s *CoreService) SpeedTest(ctx context.Context, in *SpeedTestRequest) (resp *SpeedTestResponse, err error) {
	defer config.RecoverPanicToError("CoreService.SpeedTest", func(e error) {
		Log(LogLevel_ERROR, LogType_CORE, "SpeedTest panic: ", e.Error())
		resp = &SpeedTestResponse{Error: e.Error()}
		err = nil // НЕ throw'ить gRPC error — Dart-side ждёт response с error field
	})
	return static.SpeedTest(ctx, in)
}

// SpeedTest на InhiveInstance — реальная implementация. Изолирована для
// единообразия с UrlTest pattern.
func (h *InhiveInstance) SpeedTest(ctx context.Context, in *SpeedTestRequest) (*SpeedTestResponse, error) {
	if in.OutboundTag == "" {
		return &SpeedTestResponse{Error: "outbound_tag is required"}, nil
	}

	box := h.Box()
	if box == nil {
		return &SpeedTestResponse{Error: "core not started"}, nil
	}

	// Достать outbound по tag. Может быть прямой outbound или selector group;
	// в обоих случаях DialContext делегирует на underlying outbound.
	out, isLoaded := box.Outbound().Outbound(in.OutboundTag)
	if !isLoaded {
		return &SpeedTestResponse{
			Error: fmt.Sprintf("outbound not found: %s", in.OutboundTag),
		}, nil
	}

	testBytes := in.TestBytes
	if testBytes <= 0 {
		testBytes = defaultTestBytes
	}
	timeoutSec := in.TimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = defaultTimeoutSec
	}

	// Hard timeout всего теста.
	testCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	// Один HTTP-клиент c custom Transport.DialContext который пропускает все
	// connection attempts через outbound. Pattern взят из urltest.URLTest.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dest := M.ParseSocksaddrHostPortStr(speedTestHost, speedTestPort)
				return out.DialContext(ctx, "tcp", dest)
			},
			TLSClientConfig: &tls.Config{
				Time:    ntp.TimeFuncFromContext(testCtx),
				RootCAs: adapter.RootPoolFromContext(testCtx),
			},
			DisableCompression: true, // чистый bandwidth test, без gzip
		},
		Timeout: time.Duration(timeoutSec) * time.Second,
	}
	defer client.CloseIdleConnections()

	if in.Upload {
		return runUpload(testCtx, client, testBytes)
	}
	return runDownload(testCtx, client, testBytes)
}

func runDownload(ctx context.Context, client *http.Client, bytesToFetch int64) (*SpeedTestResponse, error) {
	url := fmt.Sprintf("https://%s/__down?bytes=%d", speedTestHost, bytesToFetch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return &SpeedTestResponse{Error: E.New("build request: ", err).Error()}, nil
	}

	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return &SpeedTestResponse{Error: E.New("download request: ", err).Error()}, nil
	}
	defer resp.Body.Close()

	got, err := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(start)
	if err != nil && got == 0 {
		return &SpeedTestResponse{Error: E.New("download read: ", err).Error()}, nil
	}

	return computeKbps(got, elapsed), nil
}

func runUpload(ctx context.Context, client *http.Client, bytesToSend int64) (*SpeedTestResponse, error) {
	// Stream the body instead of allocating bytesToSend bytes up-front: at the
	// 2 MB default that's already 4% of the 50 MB iOS Network Extension budget,
	// and callers can request bigger payloads via SpeedTestRequest.TestBytes.
	// http.Transport will pull this in ~32 KB chunks; allocation is bounded.
	body := io.LimitReader(constByteReader('a'), bytesToSend)
	url := fmt.Sprintf("https://%s/__up", speedTestHost)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return &SpeedTestResponse{Error: E.New("build request: ", err).Error()}, nil
	}
	req.ContentLength = bytesToSend
	req.Header.Set("Content-Type", "application/octet-stream")

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return &SpeedTestResponse{Error: E.New("upload request: ", err).Error()}, nil
	}
	defer resp.Body.Close()
	// Drain body — иначе connection не освободится.
	_, _ = io.Copy(io.Discard, resp.Body)

	return computeKbps(bytesToSend, elapsed), nil
}

func computeKbps(bytes int64, elapsed time.Duration) *SpeedTestResponse {
	resp := &SpeedTestResponse{
		ElapsedMs:        elapsed.Milliseconds(),
		BytesTransferred: bytes,
	}
	if bytes > 0 && elapsed > 0 {
		// KB/s = bytes / 1024 / seconds. Округление вниз int.
		resp.SpeedKbps = (bytes * 1000) / (elapsed.Milliseconds() * 1024)
	}
	return resp
}

// constByteReader is an io.Reader that yields a single repeating byte forever;
// wrap it with io.LimitReader to bound the size. Used for upload speed tests
// where the actual payload contents don't matter, only the byte count and we
// want to avoid materializing the whole payload in RAM.
type constByteReader byte

func (c constByteReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(c)
	}
	return len(p), nil
}
