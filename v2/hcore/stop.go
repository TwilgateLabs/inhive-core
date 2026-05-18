// stop.go — graceful VPN service shutdown and cleanup.
package hcore

import (
	"context"
	"fmt"

	"github.com/twilgate/inhive-core/v2/config"
	hcommon "github.com/twilgate/inhive-core/v2/hcommon"
)

func (s *CoreService) Stop(ctx context.Context, empty *hcommon.Empty) (resp *CoreInfoResponse, err error) {
	defer config.RecoverPanicToError("CoreService.Stop", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp, err = errorWrapper(MessageType_UNEXPECTED_ERROR, e)
	})
	return Stop()
}

func Stop() (coreResponse *CoreInfoResponse, err error) {
	defer config.DeferPanicToError("stop", func(recovered_err error) {
		coreResponse, err = errorWrapper(MessageType_UNEXPECTED_ERROR, recovered_err)
	})

	static.lock.Lock()
	defer static.lock.Unlock()

	SetCoreStatus(CoreStates_STOPPING, MessageType_EMPTY, "")
	ss := static.StartedService
	if ss == nil {
		return SetCoreStatus(CoreStates_STOPPED, MessageType_ALREADY_STOPPED, ""), nil
	}

	if err := ss.CloseService(); err != nil {
		static.StartedService = nil
		dumpGoroutinesToFile(fmt.Sprint(sWorkingPath, "/data/goroutine-stop.log"))
		return errorWrapper(MessageType_UNEXPECTED_ERROR, err)
	}
	static.StartedService = nil

	return SetCoreStatus(CoreStates_STOPPED, MessageType_EMPTY, ""), nil
}
