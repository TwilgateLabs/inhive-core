package hcore

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/twilgate/inhive-core/v2/config"
	"github.com/twilgate/inhive-core/v2/db"
	hcommon "github.com/twilgate/inhive-core/v2/hcommon"
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

// Пункт 1 волны логов 2026-07-21: выбор TRACE/DEBUG на вкладке «Логи» обязан
// РЕАЛЬНО поднимать уровень фабрики работающего движка (иначе box.log и все
// его логгеры остаются на вмороженном конфиг-уровне warn и debug-строки
// движка не доезжают до экспорта диагностики). Проверяем фактом: настоящая
// sing-box фабрика с writer'ом в буфер — debug-строка до пуша не пишется,
// после пуша пишется, после возврата на warn снова не пишется.
func TestChangeInhiveSettings_RaisesLiveEngineLogLevel(t *testing.T) {
	prev := static.InhiveOptions
	prevLevel := static.logLevel
	prevFactory := liveBoxLogFactory
	defer func() {
		static.InhiveOptions = prev
		static.logLevel = prevLevel
		liveBoxLogFactory = prevFactory
	}()
	static.InhiveOptions = config.DefaultInhiveOptions()

	// Настоящая фабрика sing-box, как её создаёт box.New из конфига с
	// level=warn. buf играет роль box.log (тот же путь кода: файловый writer
	// фабрики режется её уровнем).
	var buf bytes.Buffer
	factory, err := log.New(log.Options{
		Context:       context.Background(),
		Options:       option.LogOptions{Level: "warn"},
		DefaultWriter: &buf,
		BaseTime:      time.Now(),
	})
	if err != nil {
		t.Fatalf("log.New: %v", err)
	}
	liveBoxLogFactory = func() log.Factory { return factory }
	logger := factory.Logger()

	logger.Debug("before-push")
	if bytes.Contains(buf.Bytes(), []byte("before-push")) {
		t.Fatalf("debug line written at factory level warn — baseline broken")
	}

	if _, err := ChangeInhiveSettings(&ChangeInhiveSettingsRequest{
		InhiveSettingsJson: `{"log-level":"debug"}`,
	}, false); err != nil {
		t.Fatalf("ChangeInhiveSettings(debug): %v", err)
	}
	if got := factory.Level(); got != log.LevelDebug {
		t.Errorf("live factory level = %v, want LevelDebug", got)
	}
	logger.Debug("after-push")
	if !bytes.Contains(buf.Bytes(), []byte("after-push")) {
		t.Errorf("debug line NOT written after push — level did not reach the live factory")
	}

	// Возврат: ALL/обычный режим пушит настроечный дефолт warn — движок не
	// должен остаться в debug/trace навсегда.
	if _, err := ChangeInhiveSettings(&ChangeInhiveSettingsRequest{
		InhiveSettingsJson: `{"log-level":"warn"}`,
	}, false); err != nil {
		t.Fatalf("ChangeInhiveSettings(warn): %v", err)
	}
	if got := factory.Level(); got != log.LevelWarn {
		t.Errorf("live factory level after restore = %v, want LevelWarn", got)
	}
	logger.Debug("after-restore")
	if bytes.Contains(buf.Bytes(), []byte("after-restore")) {
		t.Errorf("debug line written after restore to warn — level not restored")
	}
}

// Кривой уровень в partial push не должен трогать живую фабрику (ParseLevel
// при ошибке возвращает LevelTrace — молча свалиться в trace недопустимо).
func TestChangeInhiveSettings_UnknownLevelLeavesLiveFactory(t *testing.T) {
	prev := static.InhiveOptions
	prevLevel := static.logLevel
	prevFactory := liveBoxLogFactory
	defer func() {
		static.InhiveOptions = prev
		static.logLevel = prevLevel
		liveBoxLogFactory = prevFactory
	}()
	static.InhiveOptions = config.DefaultInhiveOptions()

	factory, err := log.New(log.Options{
		Context:  context.Background(),
		Options:  option.LogOptions{Level: "warn"},
		BaseTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("log.New: %v", err)
	}
	liveBoxLogFactory = func() log.Factory { return factory }

	if _, err := ChangeInhiveSettings(&ChangeInhiveSettingsRequest{
		InhiveSettingsJson: `{"log-level":"loud"}`,
	}, false); err != nil {
		t.Fatalf("ChangeInhiveSettings(loud): %v", err)
	}
	if got := factory.Level(); got != log.LevelWarn {
		t.Errorf("live factory level = %v, want untouched LevelWarn", got)
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

// Longrun-аудит 2026-09-23 §3.9: DEBUG/TRACE, выбранный фильтром вкладки «Логи»
// (partial {"log-level":X}, insert=true), живёт только в памяти — в БД ядра не
// уходит, иначе каждый следующий Setup (iOS: каждый старт NE) поднимает движок
// на debug/trace. Свойство: при ЛЮБОЙ последовательности «verbose-фильтр →
// другая настройка» персистентный уровень остаётся последним явным.
func TestChangeInhiveSettings_VerboseLogFilterNotPersisted(t *testing.T) {
	t.Chdir(t.TempDir()) // БД ядра — относительный ./data
	prev := static.InhiveOptions
	prevLevel := static.logLevel
	prevPersisted := persistedLogLevel()
	defer func() {
		static.InhiveOptions = prev
		static.logLevel = prevLevel
		setPersistedLogLevel(prevPersisted)
	}()

	base := config.DefaultInhiveOptions()
	base.LogLevel = "warn"
	static.InhiveOptions = base
	setPersistedLogLevel("warn")

	storedLevel := func() string {
		t.Helper()
		row, err := db.GetTable[hcommon.AppSettings]().Get("InHiveSettingsJson")
		if err != nil || row == nil {
			return "<none>"
		}
		var o config.InhiveOptions
		if err := json.Unmarshal([]byte(row.Value.(string)), &o); err != nil {
			t.Fatalf("stored settings unmarshal: %v", err)
		}
		return o.LogLevel
	}
	change := func(js string) {
		t.Helper()
		if _, err := ChangeInhiveSettings(&ChangeInhiveSettingsRequest{InhiveSettingsJson: js}, true); err != nil {
			t.Fatalf("ChangeInhiveSettings(%s): %v", js, err)
		}
	}

	for _, verbose := range []string{"debug", "trace"} {
		change(`{"log-level":"` + verbose + `"}`)
		if static.InhiveOptions.LogLevel != verbose {
			t.Fatalf("in-memory level = %q, want %q (filter must still apply live)", static.InhiveOptions.LogLevel, verbose)
		}
		if got := storedLevel(); got == verbose {
			t.Fatalf("verbose log filter %q was persisted to the core DB", verbose)
		}
		// Другая настройка поверх verbose-фильтра: поле пишется, уровень — последний явный.
		change(`{"region":"ru"}`)
		if got := storedLevel(); got != "warn" {
			t.Fatalf("after unrelated setting stored log-level = %q, want warn", got)
		}
	}
	// Не-verbose фильтр персистится (и лечит ранее отравленную БД).
	change(`{"log-level":"error"}`)
	if got := storedLevel(); got != "error" {
		t.Fatalf("non-verbose filter stored log-level = %q, want error", got)
	}
}
