// log_interface.go — implements sing-box PlatformWriter for structured logging.
package hcore

import (
	"github.com/twilgate/inhive-core/v2/service_manager"
	daemon "github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/log"
)

var _ log.PlatformWriter = (*LogInterface)(nil)

type LogInterface struct{}

func (h *LogInterface) ServiceStop() error {
	return service_manager.OnMainServiceClose()
}
func (h *LogInterface) ServiceReload() error {
	return service_manager.OnMainServiceStart()

}
func (h *LogInterface) SystemProxyStatus() (*daemon.SystemProxyStatus, error) {
	return nil, nil
}
func (h *LogInterface) SetSystemProxyEnabled(enabled bool) error {
	return nil
}

func (h *LogInterface) WriteDebugMessage(message string) {
	h.WriteMessage(log.LevelDebug, message)
}
func (h *LogInterface) WriteMessage(level log.Level, message string) {
	Log(convertLogLevel(level), LogType_SERVICE, message)
}
func convertLogLevel(level log.Level) LogLevel {
	// ВАЖНО: sing-box log.Level и proto LogLevel нумерованы в обратном порядке.
	// sing-box: Panic=0, Fatal=1, Error=2, Warn=3, Info=4, Debug=5, Trace=6
	// proto:    TRACE=0, DEBUG=1, INFO=2, WARNING=3, ERROR=4, FATAL=5
	// Нельзя делать numeric cast между ними — нужен явный switch для каждого case.
	switch level {
	case log.LevelTrace:
		return LogLevel_TRACE
	case log.LevelDebug:
		return LogLevel_DEBUG
	case log.LevelInfo:
		return LogLevel_INFO
	case log.LevelWarn:
		return LogLevel_WARNING
	case log.LevelError:
		return LogLevel_ERROR
	case log.LevelFatal, log.LevelPanic:
		return LogLevel_FATAL
	}
	// Неизвестный уровень — INFO как безопасный default.
	// (Раньше было LogLevel(log.LevelDebug), но log.LevelDebug=5 numerically,
	// а proto LogLevel(5)=FATAL — поэтому TRACE/PANIC показывались как FATAL.)
	return LogLevel_INFO
}
