//go:build linux && !android

package hutils

import (
	"fmt"
	"os"

	"github.com/sagernet/sing-box/experimental/libbox"
	"golang.org/x/sys/unix"
)

func RedirectStderr(path string) error {
	return libbox.RedirectStderr(path)
}

func IsAdmin() bool {
	return os.Getuid() == 0
}

func TunAllowed() bool {
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	hdr.Pid = 0 // 0 means current process

	var data unix.CapUserData
	if err := unix.Capget(&hdr, &data); err != nil {
		fmt.Print(err)
		return false //, fmt.Errorf("failed to get capabilities: %v", err)
	}
	return (data.Effective & (1 << unix.CAP_NET_ADMIN)) != 0
}
