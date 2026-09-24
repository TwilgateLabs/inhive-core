// setup.go — initializes InHive core service (DLL entry-point wiring).
package hcore

import (
	"context"

	"github.com/twilgate/inhive-core/v2/config"
	"github.com/twilgate/inhive-core/v2/hcommon"
)

var (
	sWorkingPath          string
	sTempPath             string
	sUserID               int
	sGroupID              int
	statusPropagationPort int64
)

// InitInhiveService раньше звала service_manager.StartServices(); пакет
// снесён 2026-09-24 как no-op (Register/RegisterPreService снесли 2026-09-23,
// списки services/preservices были навсегда пустыми). Функция оставлена ради
// единственного вызова из grpc_server.go — переписывать call site не стали,
// чтобы не трогать код за пределами invariant-области этой правки.
func InitInhiveService() error {
	return nil
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
