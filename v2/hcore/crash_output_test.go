package hcore

import (
	"os"
	"path/filepath"
	"testing"
)

// TestInitCrashOutput guards the crash.log wiring: the file must be created,
// and a non-empty previous crash.log (= the last run died by panic) must be
// preserved as crash.log.old instead of being truncated away — that file is
// the only evidence a silent process death leaves behind.
func TestInitCrashOutput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "crash.log")

	initCrashOutput(dir)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("crash.log not created: %v", err)
	}

	// Simulate a previous run that crashed: crash.log has content.
	if err := os.WriteFile(path, []byte("panic: boom\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	initCrashOutput(dir)
	old, err := os.ReadFile(path + ".old")
	if err != nil {
		t.Fatalf("previous crash dump must survive as crash.log.old: %v", err)
	}
	if string(old) != "panic: boom\n" {
		t.Fatalf("crash.log.old content mangled: %q", old)
	}
	if st, err := os.Stat(path); err != nil || st.Size() != 0 {
		t.Fatalf("fresh crash.log must exist empty, got err=%v size=%d", err, st.Size())
	}
}
