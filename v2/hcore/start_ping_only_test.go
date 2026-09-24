package hcore

import (
	"os"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/twilgate/inhive-core/v2/config"
	"github.com/twilgate/inhive-core/v2/db"
	hcommon "github.com/twilgate/inhive-core/v2/hcommon"
)

// Аудит 2026-09-25, топ №1: headless-старт (Android QS-плитка, always-on /
// START_STICKY) реплеит last-start из БД ядра. Если last-start записал
// ping-only старт (фоновое ядро для пингов без TUN), плитка «горит», а
// туннеля нет. Свойство узла: last-start пишет ТОЛЬКО старт с намерением
// «подключиться»; ping-only старт его не трогает — в любом порядке.
//
// Тест идёт через StartService (узел), а не через saveLastStartRequest, чтобы
// ловить и регресс «кто-то снова зовёт save мимо признака».

// pingOnlyTestEnv изолирует рабочий каталог и БД ядра в t.TempDir().
func pingOnlyTestEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll("data", 0o755); err != nil {
		t.Fatal(err)
	}
	// libbox.Setup проставляет uid/gid процесса: без него filemanager зовёт
	// chown(0,0) на cache.db (на Windows «not supported», на Linux не-root —
	// EPERM) и NewService падает, не дойдя до работающего бокса.
	if err := libbox.Setup(&libbox.SetupOptions{BasePath: dir, WorkingPath: dir, TempPath: dir}); err != nil {
		t.Fatal(err)
	}
	prevWorking, prevOpts := sWorkingPath, static.InhiveOptions
	sWorkingPath = dir
	if static.InhiveOptions == nil {
		static.InhiveOptions = config.DefaultInhiveOptions()
	}
	t.Cleanup(func() {
		_, _ = Stop()
		_ = libbox.Setup(&libbox.SetupOptions{})
		sWorkingPath, static.InhiveOptions = prevWorking, prevOpts
		_ = os.Chdir(cwd)
	})
}

func lastStartContent(t *testing.T) string {
	t.Helper()
	v, err := db.GetTable[hcommon.AppSettings]().Get("lastStartRequestContent")
	if err != nil || v == nil {
		return ""
	}
	s, _ := v.Value.(string)
	return s
}

func startAndStop(t *testing.T, req *StartRequest) {
	t.Helper()
	resp, err := StartService(libbox.BaseContext(nil), req)
	if err != nil {
		t.Fatalf("StartService: %v", err)
	}
	if resp.MessageType != MessageType_EMPTY {
		t.Fatalf("StartService: %v %s", resp.MessageType, resp.Message)
	}
	if _, err := Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

const (
	connectCfg  = `{"outbounds":[{"type":"direct","tag":"connect-direct"}]}`
	pingOnlyCfg = `{"outbounds":[{"type":"direct","tag":"ping-direct"}]}`
)

func TestStartServicePingOnlyDoesNotWriteLastStart(t *testing.T) {
	pingOnlyTestEnv(t)

	startAndStop(t, &StartRequest{ConfigContent: connectCfg, EnableRawConfig: true})
	if got := lastStartContent(t); got != connectCfg {
		t.Fatalf("connect-старт обязан писать last-start: got %q", got)
	}

	startAndStop(t, &StartRequest{ConfigContent: pingOnlyCfg, EnableRawConfig: true, PingOnly: true})
	if got := lastStartContent(t); got != connectCfg {
		t.Fatalf("ping-only старт перезаписал last-start (headless-реплей "+
			"поднимет ядро без TUN): got %q, want connect-конфиг", got)
	}

	// Реплей пустым запросом (путь плитки) поднимает именно connect-конфиг.
	replayed, err := loadLastStartRequestIfNeeded(&StartRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if replayed.ConfigContent != connectCfg {
		t.Fatalf("реплей плитки: got %q, want connect-конфиг", replayed.ConfigContent)
	}
	if replayed.PingOnly {
		t.Fatal("реплей плитки обязан быть connect-стартом (PingOnly=false)")
	}
}

// Порядок входов не важен: ping-only ДО первого connect не оставляет
// last-start вовсе (плитке честно нечего реплеить), а следующий connect пишет.
func TestStartServicePingOnlyFirstLeavesNoLastStart(t *testing.T) {
	pingOnlyTestEnv(t)

	startAndStop(t, &StartRequest{ConfigContent: pingOnlyCfg, EnableRawConfig: true, PingOnly: true})
	if got := lastStartContent(t); got != "" {
		t.Fatalf("ping-only старт на чистой БД записал last-start: %q", got)
	}
	startAndStop(t, &StartRequest{ConfigContent: connectCfg, EnableRawConfig: true})
	if got := lastStartContent(t); got != connectCfg {
		t.Fatalf("connect после ping-only: got %q", got)
	}
}
