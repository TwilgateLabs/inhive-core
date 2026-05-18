package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"runtime/debug"
	"unsafe"

	"github.com/twilgate/inhive-core/cmd"
	"github.com/sagernet/sing-box/log"
)

//export parseCli
func parseCli(argc C.int, argv **C.char) (result *C.char) {
	defer func() {
		if r := recover(); r != nil {
			msg := fmt.Sprintf("parseCli panic: %v\n%s", r, string(debug.Stack()))
			log.Error(msg)
			result = C.CString(msg)
		}
	}()
	args := make([]string, argc)
	for i := 0; i < int(argc); i++ {
		// fmt.Println("parseCli", C.GoString(*argv))
		args[i] = C.GoString(*argv)
		argv = (**C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(argv)) + uintptr(unsafe.Sizeof(*argv))))
	}
	err := cmd.ParseCli(args[1:])
	if err != nil {
		return C.CString(err.Error())
	}
	return C.CString("")
}
