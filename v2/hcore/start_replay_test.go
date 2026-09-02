package hcore

import (
	"os"
	"testing"
)

// Полевой баг 2026-09-02 (Android QS-плитка): headless-реплей последнего
// профиля (пустой StartRequest → loadLastStartRequestIfNeeded) терял
// EnableRawConfig — флаг не персистится в БД, восстановленный запрос шёл с
// false → deprecated InhiveOptions-транслятор → FATAL «unknown load balance
// strategy» → «плитка горит и сама гаснет». Реплей ОБЯЗАН идти raw-путём:
// сохранённый content всегда записан raw-writer'ами.
func TestLoadLastStartRequestRestoresRawConfigFlag(t *testing.T) {
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(cwd) }()
	if err := os.MkdirAll("data", 0o755); err != nil {
		t.Fatal(err)
	}

	saved := &StartRequest{
		ConfigContent:   `{"outbounds":[]}`,
		ConfigName:      "test-profile",
		EnableRawConfig: true,
	}
	if err := saveLastStartRequest(saved); err != nil {
		t.Fatalf("saveLastStartRequest: %v", err)
	}

	restored, err := loadLastStartRequestIfNeeded(&StartRequest{})
	if err != nil {
		t.Fatalf("loadLastStartRequestIfNeeded: %v", err)
	}
	if restored.ConfigContent != saved.ConfigContent {
		t.Errorf("ConfigContent = %q, want roundtrip", restored.ConfigContent)
	}
	if restored.ConfigName != "test-profile" {
		t.Errorf("ConfigName = %q, want test-profile", restored.ConfigName)
	}
	if !restored.EnableRawConfig {
		t.Fatalf("EnableRawConfig = false after replay — restored request would " +
			"fall into the deprecated InhiveOptions translator (FATAL balancer)")
	}

	// Явный запрос с контентом проходит как есть — реплей его не подменяет.
	explicit := &StartRequest{ConfigContent: "x", EnableRawConfig: false}
	passthrough, err := loadLastStartRequestIfNeeded(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if passthrough != explicit {
		t.Errorf("explicit request must pass through untouched")
	}
}
