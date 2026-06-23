package main

/*
#include <stdlib.h>
#include <signal.h>
#include "stdint.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strconv"
	"unsafe"

	hcore "github.com/twilgate/inhive-core/v2/hcore"
	ray2sing "github.com/twilgate/xray2sing/ray2sing"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/log"
)

func main() {}

//export cleanup
func cleanup() {}

func emptyOrErrorC(err error) *C.char {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err == nil {
		return C.CString("")
	}
	log.Error(err.Error())
	return C.CString(err.Error())
}

//export setup
func setup(baseDir *C.char, workingDir *C.char, tempDir *C.char, mode C.int, listen *C.char, secret *C.char, statusPort C.longlong, debug_ bool) (result *C.char) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("setup panic: %v\n%s", r, string(debug.Stack()))
			log.Error(msg)
			result = C.CString(msg)
		}
	}()
	params := hcore.SetupRequest{
		BasePath:          C.GoString(baseDir),
		WorkingDir:        C.GoString(workingDir),
		TempDir:           C.GoString(tempDir),
		FlutterStatusPort: int64(statusPort),
		Debug:             bool(debug_),
		Mode:              hcore.SetupMode(mode),
		Listen:            C.GoString(listen),
		Secret:            C.GoString(secret),
	}

	err := hcore.Setup(&params, nil)
	return emptyOrErrorC(err)
}

// parse converts subscription content (base64 list / newline-separated share-link
// URIs / Xray-or-sing-box JSON) into a sing-box config JSON via the canonical
// xray2sing parser — the SINGLE source of truth, mirroring the gomobile
// MobileParse export (platform/mobile/mobile.go). Pure function: no setup() or
// running engine required (Ray2Singbox uses libbox.BaseContext internally), so
// the Flutter app can call it on Windows before the VPN is up. Returns marshaled
// {"outbounds":[...],"endpoints":[...]}. On error returns a JSON object with a
// single "__parse_error__" key (C ABI has no exceptions); the Dart side checks
// for that key. Caller must freeString the result.
//
//export parse
func parse(content *C.char) (result *C.char) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("parse panic: %v\n%s", r, string(debug.Stack()))
			log.Error(msg)
			result = C.CString(`{"__parse_error__":` + strconv.Quote(msg) + `}`)
		}
	}()
	out, err := ray2sing.Ray2Singbox(libbox.BaseContext(nil), C.GoString(content), false)
	if err != nil {
		log.Error("parse: " + err.Error())
		return C.CString(`{"__parse_error__":` + strconv.Quote(err.Error()) + `}`)
	}
	return C.CString(string(out))
}

//export freeString
func freeString(str *C.char) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	C.free(unsafe.Pointer(str))
}

//export start
func start(configPath *C.char, disableMemoryLimit bool) (result *C.char) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("start panic: %v\n%s", r, string(debug.Stack()))
			log.Error(msg)
			result = C.CString(msg)
		}
	}()
	ctx := libbox.BaseContext(nil)
	_, err := hcore.Start(ctx, &hcore.StartRequest{
		ConfigPath:             C.GoString(configPath),
		EnableOldCommandServer: true,
		DisableMemoryLimit:     bool(disableMemoryLimit),
	})
	return emptyOrErrorC(err)
}

//export stop
func stop() (result *C.char) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("stop panic: %v\n%s", r, string(debug.Stack()))
			log.Error(msg)
			result = C.CString(msg)
		}
	}()
	_, err := hcore.Stop()
	return emptyOrErrorC(err)
}

//export restart
func restart(configPath *C.char, disableMemoryLimit bool) (result *C.char) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("restart panic: %v\n%s", r, string(debug.Stack()))
			log.Error(msg)
			result = C.CString(msg)
		}
	}()
	ctx := libbox.BaseContext(nil)
	_, err := hcore.Restart(ctx, &hcore.StartRequest{
		ConfigPath:             C.GoString(configPath),
		EnableOldCommandServer: true,
		DisableMemoryLimit:     bool(disableMemoryLimit),
	})
	return emptyOrErrorC(err)
}

//export GetServerPublicKey
func GetServerPublicKey() (result *C.char) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("GetServerPublicKey panic: %v\n%s", r, string(debug.Stack()))
			log.Error(msg)
			result = C.CString(msg)
		}
	}()
	publicKey := hcore.GetGrpcServerPublicKey()
	return C.CString(string(publicKey))
}

//export AddGrpcClientPublicKey
func AddGrpcClientPublicKey(clientPublicKey *C.char) (result *C.char) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("AddGrpcClientPublicKey panic: %v\n%s", r, string(debug.Stack()))
			log.Error(msg)
			result = C.CString(msg)
		}
	}()
	clientKey := C.GoBytes(unsafe.Pointer(clientPublicKey), C.int(len(C.GoString(clientPublicKey))))
	err := hcore.AddGrpcClientPublicKey(clientKey)
	return emptyOrErrorC(err)
}

//export closeGrpc
func closeGrpc(mode C.int) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("closeGrpc panic: %v\n%s", r, string(debug.Stack()))
			log.Error(msg)
		}
	}()
	hcore.Close(hcore.SetupMode(mode))
}
