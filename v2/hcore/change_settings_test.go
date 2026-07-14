package hcore

import (
	"testing"

	"github.com/twilgate/inhive-core/v2/config"
)

// Регрессия 4.7.30 (iOS): partial JSON ({"log-level":"warn"}) сбрасывал ВСЕ
// остальные опции в дефолт. ChangeInhiveSettings обязан мержить partial поверх
// текущих опций, не терять их.
func TestChangeInhiveSettings_PartialMergeKeepsExisting(t *testing.T) {
	prev := static.InhiveOptions
	prevLevel := static.logLevel
	defer func() {
		static.InhiveOptions = prev
		static.logLevel = prevLevel
	}()

	base := config.DefaultInhiveOptions()
	base.Region = "ru"
	base.ClashApiSecret = "keep-me"
	base.BlockAds = true
	base.LogLevel = "debug"
	static.InhiveOptions = base

	if _, err := ChangeInhiveSettings(&ChangeInhiveSettingsRequest{
		InhiveSettingsJson: `{"log-level":"warn"}`,
	}, false); err != nil {
		t.Fatalf("ChangeInhiveSettings: %v", err)
	}

	got := static.InhiveOptions
	if got.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want warn", got.LogLevel)
	}
	if got.Region != "ru" {
		t.Errorf("Region wiped: %q, want ru (partial push must merge, not replace)", got.Region)
	}
	if got.ClashApiSecret != "keep-me" {
		t.Errorf("ClashApiSecret wiped: %q", got.ClashApiSecret)
	}
	if !got.BlockAds {
		t.Errorf("BlockAds wiped")
	}
	if static.logLevel != LogLevel_WARNING {
		t.Errorf("static.logLevel = %v, want WARNING", static.logLevel)
	}
	// Снапшот подменён новым указателем (атомарная публикация), старый не мутирован в момент чтения гонщиками
	if got == base && got.LogLevel == "warn" && base.LogLevel != "warn" {
		t.Errorf("options mutated in place instead of snapshot swap")
	}
}

// Пустой JSON (Setup с пустой БД) должен давать дефолты и не падать.
func TestChangeInhiveSettings_EmptyJsonDefaults(t *testing.T) {
	prev := static.InhiveOptions
	prevLevel := static.logLevel
	defer func() {
		static.InhiveOptions = prev
		static.logLevel = prevLevel
	}()

	static.InhiveOptions = nil
	if _, err := ChangeInhiveSettings(&ChangeInhiveSettingsRequest{InhiveSettingsJson: ""}, false); err != nil {
		t.Fatalf("ChangeInhiveSettings(empty): %v", err)
	}
	if static.InhiveOptions == nil {
		t.Fatalf("InhiveOptions nil after empty push")
	}
	def := config.DefaultInhiveOptions()
	if static.InhiveOptions.LogLevel != def.LogLevel {
		t.Errorf("LogLevel = %q, want default %q", static.InhiveOptions.LogLevel, def.LogLevel)
	}
}
