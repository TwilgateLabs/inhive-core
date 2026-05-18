// setup.go — initializes InHive core service (DLL entry-point wiring).
package hcore

import (
	"context"

	"github.com/twilgate/inhive-core/v2/config"
	"github.com/twilgate/inhive-core/v2/hcommon"
	"github.com/twilgate/inhive-core/v2/service_manager"
)

var (
	sWorkingPath          string
	sTempPath             string
	sUserID               int
	sGroupID              int
	statusPropagationPort int64
)

func InitInhiveService() error {
	return service_manager.StartServices()
}

func (s *CoreService) Setup(ctx context.Context, req *SetupRequest) (resp *hcommon.Response, err error) {
	defer config.RecoverPanicToError("CoreService.Setup", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp = &hcommon.Response{Code: hcommon.ResponseCode_FAILED, Message: e.Error()}
		err = e
	})
	if grpcServer[req.Mode] != nil {
		return &hcommon.Response{Code: hcommon.ResponseCode_OK, Message: ""}, nil
	}
	err = Setup(req, nil)
	code := hcommon.ResponseCode_OK
	if err != nil {
		code = hcommon.ResponseCode_FAILED
	}
	return &hcommon.Response{Code: code, Message: err.Error()}, err
}
