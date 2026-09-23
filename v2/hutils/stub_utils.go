//go:build (!linux && !windows) || android

package hutils

import "os"

func TunAllowed() bool {
	return false
}

func IsAdmin() bool {
	return os.Getuid() == 0
}
