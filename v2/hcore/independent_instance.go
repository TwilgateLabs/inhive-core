// independent_instance.go — standalone proxy instances for testing and extensions.
package hcore

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/twilgate/inhive-core/v2/config"
	"golang.org/x/net/proxy"

	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

// getRandomAvailblePort: best-effort port allocation. There IS a TOCTOU race
// between Close() and sing-box bind — under heavy parallel BootstrapFetch load
// two side-instances may pick the same port. Caller of RunInstance/Quiet should
// retry on bind failure. Mitigated by binding to 127.0.0.1 specifically (not
// :0) which narrows the race window vs all-interfaces.
func getRandomAvailblePort() (uint16, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("getRandomAvailblePort: %w", err)
	}
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	listener.Close()
	return port, nil
}

func RunInstanceString(ctx context.Context, inhiveSettings *config.InhiveOptions, proxiesInput string) (*InhiveInstance, error) {
	if inhiveSettings == nil {
		inhiveSettings = config.DefaultInhiveOptions()
	}

	singconfigs, err := config.ParseConfig(ctx, &config.ReadOptions{Content: proxiesInput}, true, inhiveSettings, false)
	if err != nil {
		return nil, err
	}
	return RunInstance(ctx, inhiveSettings, singconfigs)
}

func RunInstance(ctx context.Context, inhiveSettings *config.InhiveOptions, singconfig *option.Options) (instance *InhiveInstance, err error) {
	defer config.RecoverPanicToError("RunInstance", func(panicErr error) { err = panicErr })
	hservice, err := runInstanceCore(ctx, inhiveSettings, singconfig)
	if err != nil {
		return nil, err
	}
	// Warm-up probe — verifies that the freshly started side-instance can actually
	// reach the open Internet through its outbound chain. Used by cmd_instance and
	// profile_repository which want a hard "is this config alive" signal.
	hservice.PingCloudflare()
	return hservice, nil
}

// RunInstanceQuiet is the same as RunInstance but skips the PingCloudflare end-of-boot
// probe. The probe targets cp.cloudflare.com which is blocked on RU LTE carriers
// (Megafon / Beeline / MTS / Tele2 / Yota) — the 4-second timeout would be charged
// to every BootstrapFetch call on our main audience. Callers that already plan to
// drive their own HTTP request through the side-instance (Wave 13D BootstrapFetch)
// do not need the probe and should use this variant.
func RunInstanceQuiet(ctx context.Context, inhiveSettings *config.InhiveOptions, singconfig *option.Options) (instance *InhiveInstance, err error) {
	defer config.RecoverPanicToError("RunInstanceQuiet", func(panicErr error) { err = panicErr })
	return runInstanceCore(ctx, inhiveSettings, singconfig)
}

func runInstanceCore(ctx context.Context, inhiveSettings *config.InhiveOptions, singconfig *option.Options) (*InhiveInstance, error) {
	if inhiveSettings == nil {
		inhiveSettings = config.DefaultInhiveOptions()
	}
	inhiveSettings.EnableClashApi = false
	port, err := getRandomAvailblePort()
	if err != nil {
		return nil, err
	}
	inhiveSettings.InboundOptions.MixedPort = port
	inhiveSettings.InboundOptions.EnableTun = false
	inhiveSettings.InboundOptions.EnableTunService = false
	inhiveSettings.InboundOptions.SetSystemProxy = false
	inhiveSettings.InboundOptions.TProxyPort = 0
	inhiveSettings.InboundOptions.DirectPort = 0
	inhiveSettings.InboundOptions.RedirectPort = 0
	inhiveSettings.Region = "other"
	inhiveSettings.BlockAds = false
	inhiveSettings.LogFile = os.DevNull
	// BuildConfig adds a balancer outbound — strategy must be non-empty.
	if inhiveSettings.BalancerStrategy == "" {
		inhiveSettings.BalancerStrategy = "round-robin"
	}

	finalConfigs, err := config.BuildConfig(ctx, inhiveSettings, &config.ReadOptions{Options: singconfig})
	if err != nil {
		return nil, err
	}

	// Bootstrap side-instance: use a no-op PlatformHandler so box does NOT set
	// options.PlatformLogWriter, which would enable CacheFile and conflict with
	// the main instance's exclusive lock on data/clash.db.
	if err := libbox.CheckConfigOptions(finalConfigs); err != nil {
		return nil, err
	}
	svc := daemon.NewStartedService(daemon.ServiceOptions{
		Context:             ctx,
		Debug:               static.debug,
		LogMaxLines:         0,
		Handler:             &noopPlatformHandler{},
		NoPlatformLogWriter: true,
	})
	if err := svc.StartOrReloadServiceOptions(*finalConfigs); err != nil {
		return nil, err
	}
	instance := svc

	// Settle delay — даём time для async init outbounds. Honour ctx cancellation
	// (раньше hardcoded 250ms блокировал даже когда caller отменил context).
	select {
	case <-time.After(250 * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &InhiveInstance{
		StartedService: instance,
		ListenPort:     inhiveSettings.InboundOptions.MixedPort,
	}, nil
}

// dialer, err := s.libbox.GetInstance().Router().Dialer(context.Background())

func (s *InhiveInstance) Close() error {
	return s.StartedService.CloseService()
}

func (s *InhiveInstance) GetContent(url string) (string, error) {
	return s.ContentFromURL("GET", url, 10*time.Second)
}

func (s *InhiveInstance) ContentFromURL(method string, url string, timeout time.Duration) (string, error) {
	if method == "" {
		return "", fmt.Errorf("empty method")
	}
	if url == "" {
		return "", fmt.Errorf("empty url")
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return "", err
	}

	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", s.ListenPort), nil, proxy.Direct)
	if err != nil {
		return "", err
	}

	transport := &http.Transport{
		Dial: dialer.Dial,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return "", fmt.Errorf("request failed with status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	if body == nil {
		return "", fmt.Errorf("empty body")
	}

	return string(body), nil
}

func (s *InhiveInstance) PingCloudflare() (time.Duration, error) {
	return s.Ping("http://cp.cloudflare.com")
}

func (s *InhiveInstance) PingAverage(url string, count int) (time.Duration, error) {
	if count <= 0 {
		return -1, fmt.Errorf("count must be greater than 0")
	}

	var sum int64
	realCount := 0
	for i := 0; i < count; i++ {
		delay, err := s.Ping(url)
		if err == nil {
			realCount++
			sum += delay.Milliseconds()
		} else if realCount == 0 && i > count/2 {
			return -1, fmt.Errorf("ping average failed")
		}
	}
	if realCount == 0 {
		// Все пинги failed — возвращаем error, иначе division by zero ниже.
		return -1, fmt.Errorf("all %d pings failed", count)
	}
	// time.Duration(sum) is in nanoseconds; we have ms — multiply BEFORE divide
	// to avoid integer truncation (sum=15ms, count=2 → 7.5ms not 7ms).
	return time.Duration(sum) * time.Millisecond / time.Duration(realCount), nil
}

func (s *InhiveInstance) Ping(url string) (time.Duration, error) {
	startTime := time.Now()
	_, err := s.ContentFromURL("HEAD", url, 4*time.Second)
	if err != nil {
		return -1, err
	}
	duration := time.Since(startTime)
	return duration, nil
}

// noopPlatformHandler implements daemon.PlatformHandler with no-ops.
// Used for bootstrap side-instances where we don't want a real handler
// but also can't pass nil (daemon calls handler methods unconditionally).
type noopPlatformHandler struct{}

func (*noopPlatformHandler) ServiceStop() error                                { return nil }
func (*noopPlatformHandler) ServiceReload() error                              { return nil }
func (*noopPlatformHandler) SystemProxyStatus() (*daemon.SystemProxyStatus, error) { return nil, nil }
func (*noopPlatformHandler) SetSystemProxyEnabled(bool) error                  { return nil }
func (*noopPlatformHandler) WriteDebugMessage(string)                          {}
