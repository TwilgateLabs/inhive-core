// restart.go — restarts VPN service (stop + start) with state preservation.
package hcore

import (
	"context"
	"time"

	"github.com/twilgate/inhive-core/v2/config"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
)

func (s *CoreService) Restart(ctx context.Context, in *StartRequest) (resp *CoreInfoResponse, err error) {
	defer config.RecoverPanicToError("CoreService.Restart", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp, err = errorWrapper(MessageType_UNEXPECTED_ERROR, e)
	})
	return Restart(static.BaseContext, in)
}

func Restart(ctx context.Context, in *StartRequest) (coreResponse *CoreInfoResponse, err error) {
	defer config.DeferPanicToError("restart", func(recovered_err error) {
		coreResponse, err = errorWrapper(MessageType_UNEXPECTED_ERROR, recovered_err)
	})
	log.Debug("[Service] Restarting")

	resp, err := Stop()
	if err != nil {
		return resp, err
	}

	if C.IsAndroid && static.InhiveOptions.EnableTun {
		select {
		case <-ctx.Done():
			return SetCoreStatus(CoreStates_STOPPED, MessageType_INSTANCE_NOT_STARTED, "restart cancelled"), nil
		case <-time.After(time.Second):
		}
	}
	return StartService(ctx, in)
}
