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
	systemInfoObserver        *monitoring.Broadcaster[*SystemInfo]
	outboundsInfoObserver     *monitoring.Broadcaster[*OutboundGroupList]
	mainOutboundsInfoObserver *monitoring.Broadcaster[*OutboundGroupList]
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
}

var static = &InhiveInstance{
	CoreState:                 CoreStates_STOPPED,
	coreInfoObserver:          monitoring.NewBroadcaster[*CoreInfoResponse](context.Background()),
	logObserver:               monitoring.NewBroadcaster[*LogMessage](context.Background()),
	systemInfoObserver:        monitoring.NewBroadcaster[*SystemInfo](context.Background()),
	outboundsInfoObserver:     monitoring.NewBroadcaster[*OutboundGroupList](context.Background()),
	mainOutboundsInfoObserver: monitoring.NewBroadcaster[*OutboundGroupList](context.Background()),
	modeStateObserver:         monitoring.NewBroadcaster[*ModeStateResponse](context.Background()),
}

func init() {
	// Default mode 1 (sing-box primary). Set explicitly so it survives any
	// later refactor that re-zeroes the static struct.
	static.currentMode.Store(1)
}
