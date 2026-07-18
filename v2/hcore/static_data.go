// static_data.go — global InhiveInstance holding service state and context.
package hcore

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/twilgate/inhive-core/v2/config"
	"github.com/sagernet/sing-box/common/monitoring"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
)

type InhiveInstance struct {
	StartedService *daemon.StartedService
	InhiveOptions *config.InhiveOptions
	// activeConfigPath string
	CoreLogFactory            log.Factory
	coreInfoObserver          *monitoring.Broadcaster[*CoreInfoResponse]
	CoreState                 CoreStates
	logObserver               *monitoring.Broadcaster[*LogMessage]
	// systemInfoObserver/outboundsInfoObserver/mainOutboundsInfoObserver
	// удалены (NE-quiescence 2026-07-19): dead code. Соответствующие RPC идут
	// другим путём — SystemInfo через per-subscriber тикер (commands.go),
	// Outbounds/MainOutbounds через AllProxiesInfoStream (proxy_info.go). Эти
	// три Broadcaster'а никто не Publish/Subscribe, но каждый держал горутину
	// watchContext навсегда.
	lock                      sync.Mutex
	globalPlatformInterface   libbox.PlatformInterface
	previousStartRequest      *StartRequest
	debug                     bool
	ListenPort                uint16
	BaseContext               context.Context
	endPauseTimer             *time.Timer // only for ios

	logLevel LogLevel

	// Phase 2 — generic mode switching state.
	//
	// currentMode is the *desired* mode persisted by SwitchMode and consulted
	// by the watcher. Default 1 (primary sing-box carousel). Stored atomically
	// because it's read by the watcher goroutine on every probe-window tick
	// and written by gRPC handlers.
	currentMode      atomic.Int32
	modeStateObserver *monitoring.Broadcaster[*ModeStateResponse]
	// modeWatcherCancel tears down the active urltest watcher when the VPN
	// service stops or restarts. Nil when no service is running.
	modeWatcherCancel context.CancelFunc
	modeWatcherMu     sync.Mutex

	// memSamplerCancel гасит read-only сэмплер памяти (mem_sampler.go) при
	// остановке/рестарте ядра. Nil когда сэмплер не запущен.
	memSamplerCancel context.CancelFunc
	memSamplerMu     sync.Mutex

	// startCancel отменяет блокирующий olcrtc-старт (primary awaitReady, до ~30с)
	// когда юзер отменяет connect повторным тапом (Dart → Stop). Хранится ОТДЕЛЬНО
	// от lock: StartService держит static.lock весь блокирующий старт, поэтому Stop
	// не может взять lock, пока не прервёт старт через этот cancel. Nil когда нет
	// активного STARTING. См. start.go (set/clear) и stop.go (abort до lock).
	startCancel   context.CancelFunc
	startCancelMu sync.Mutex
}

var static = &InhiveInstance{
	CoreState:                 CoreStates_STOPPED,
	coreInfoObserver:          monitoring.NewBroadcaster[*CoreInfoResponse](context.Background()),
	logObserver:               monitoring.NewBroadcaster[*LogMessage](context.Background()),
	modeStateObserver:         monitoring.NewBroadcaster[*ModeStateResponse](context.Background()),
}

func init() {
	// Default mode 1 (sing-box primary). Set explicitly so it survives any
	// later refactor that re-zeroes the static struct.
	static.currentMode.Store(1)
}

// setStartCancel сохраняет cancel блокирующего старта. Defensive: отменяет
// предыдущий если остался (при сериализованном через static.lock старте не
// должно случаться).
func (s *InhiveInstance) setStartCancel(cancel context.CancelFunc) {
	s.startCancelMu.Lock()
	if s.startCancel != nil {
		s.startCancel()
	}
	s.startCancel = cancel
	s.startCancelMu.Unlock()
}

// clearStartCancel забывает cancel после того как старт завершился (успехом или
// ошибкой). НЕ отменяет: на успехе startCtx должен жить дальше под работающим
// box (он дериватив static.BaseContext, не request-scoped).
func (s *InhiveInstance) clearStartCancel() {
	s.startCancelMu.Lock()
	s.startCancel = nil
	s.startCancelMu.Unlock()
}

// abortStart прерывает идущий блокирующий старт, если он есть. Зовётся из Stop()
// ДО взятия static.lock. No-op когда старта нет (ref уже nil — после успеха
// очищен через clearStartCancel). Cancel читаем под мьютексом, зовём вне —
// context.CancelFunc идемпотентна и потокобезопасна.
func (s *InhiveInstance) abortStart() {
	s.startCancelMu.Lock()
	cancel := s.startCancel
	s.startCancelMu.Unlock()
	if cancel != nil {
		Log(LogLevel_INFO, LogType_CORE, "abortStart: cancelling in-flight connect")
		cancel()
	}
}
