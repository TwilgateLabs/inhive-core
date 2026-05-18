package main

import "C"

import (
	"fmt"
	"runtime/debug"

	hcore "github.com/twilgate/inhive-core/v2/hcore"
	"github.com/sagernet/sing-box/log"
)

//export StartCoreGrpcServer
func StartCoreGrpcServer(listenAddress *C.char) (CErr *C.char) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("StartCoreGrpcServer panic: %v\n%s", r, string(debug.Stack()))
			log.Error(msg)
			CErr = C.CString(msg)
		}
	}()
	_, err := hcore.StartCoreGrpcServer(C.GoString(listenAddress))
	return emptyOrErrorC(err)
}
