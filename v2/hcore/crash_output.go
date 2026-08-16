// crash_output.go — dedicated post-mortem file for fatal Go runtime crashes.
//
// Why it exists (field crash 2026-08-16, unreportable-bug-class): an
// unrecovered panic in ANY goroutine kills the whole process, and neither the
// gRPC recovery interceptors nor any handler-level RecoverPanicToError can see
// it. The runtime prints the stack to stderr — which the Flutter host on
// Windows does not capture, so the app just vanishes with app.log/box.log
// silent. hutils.RedirectStderr already re-points the OS stderr into
// data/stderr<mode>.log, but that is a shared, append-only stream that
// anything native can scribble into or re-point away. debug.SetCrashOutput is
// the runtime's own guaranteed channel for exactly this: on a fatal crash the
// full panic + goroutine dump is written to this file regardless of where
// stderr points. One look at data/crash.log answers "did the core die by
// panic, and where" — the class of silent deaths becomes observable.
package hcore

import (
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
)

var crashOutputOnce sync.Once

// setupCrashOutput routes fatal runtime output to <dir>/crash.log. A previous
// non-empty crash.log (= the last run actually crashed) is preserved as
// crash.log.old so one crash survives until the next one. Errors are swallowed:
// a diagnostics file must never fail core Setup. Safe to call repeatedly
// (Android reconnect re-runs Setup) — the runtime holds a duplicated fd, so
// this is wired once per process.
func setupCrashOutput(dir string) {
	crashOutputOnce.Do(func() { initCrashOutput(dir) })
}

// initCrashOutput does the actual wiring; split from the Once wrapper so tests
// can exercise create + rotate without process-global state games.
func initCrashOutput(dir string) {
	path := filepath.Join(dir, "crash.log")
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		_ = os.Rename(path, path+".old")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return
	}
	// SetCrashOutput duplicates the descriptor; close ours either way.
	_ = debug.SetCrashOutput(f, debug.CrashOptions{})
	_ = f.Close()
}
