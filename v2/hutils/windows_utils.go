//go:build windows

package hutils

import (
	"os"

	"golang.org/x/sys/windows"
)

// RedirectStderr redirects native stderr (Win32 STD_ERROR_HANDLE — used by cgo and
// crashing Go runtime) and Go's os.Stderr (used by panic stack dumps) to path.
// File is left open intentionally so writes survive until process exit.
func RedirectStderr(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	if err := windows.SetStdHandle(windows.STD_ERROR_HANDLE, windows.Handle(f.Fd())); err != nil {
		f.Close()
		return err
	}
	os.Stderr = f
	return nil
}

func IsAdmin() bool {
	adminSID, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	token := windows.Token(0)
	isMember, err := token.IsMember(adminSID)
	if err != nil {
		return false
	}
	return isMember
}

var TunAllowed = IsAdmin
