//go:build windows

package hutils

import (
	"os"
	"strings"
	"syscall"

	acl "github.com/hectane/go-acl"

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

func ExecuteCmd(exe string, background bool, args ...string) (string, error) {
	verb := "runas"
	cwd, err := os.Getwd() // Error handling added
	if err != nil {
		return "", err
	}

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(strings.Join(args, " "))

	var showCmd int32 = 0 // SW_NORMAL

	err = windows.ShellExecute(0, verbPtr, exePtr, argPtr, cwdPtr, showCmd)
	if err != nil {
		return "", err
	}
	return "", nil
}

func chmod(path string, mode os.FileMode) error {
	return acl.Chmod(path, mode)
}
