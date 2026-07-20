// log_level.go — проброс log-level в фабрику логгера РАБОТАЮЩЕГО sing-box.
//
// Зачем: уровень фабрики движка фиксируется в момент старта туннеля из JSON
// конфига (Dart шлёт settings.logLevel, по умолчанию "warn") и раньше НИКОГДА
// не менялся у живого box'а. gRPC-стрим вкладки «Логи» это не ломало —
// PlatformWriter получает строки ВСЕХ уровней в обход уровня фабрики (см.
// регрессионный тест TestPlatformWriterReceivesAllLevels в sing-box/log) — но
// box.log пишется файловым writer'ом фабрики, который уровнем режется: при
// factory=warn debug/trace строки движка (DNS, TLS, маршруты) в файл не
// попадали никогда, и экспорт диагностики был слеп к ним даже в отладочном
// режиме. Теперь ChangeInhiveSettings доносит уровень до живой фабрики.
package hcore

import (
	"github.com/sagernet/sing-box/log"
)

// liveBoxLogFactory возвращает фабрику логгера работающего box'а или nil,
// когда туннель не запущен. Указатель StartedService читается без static.lock —
// тот же lock-free паттерн, что у остальных читателей (commands.go,
// mem_sampler.go): видим либо nil, либо целиком живой инстанс.
//
// Переменная, а не функция — тестовый шов: change_settings_test подменяет её
// фабрикой без подъёма настоящего движка.
var liveBoxLogFactory = func() log.Factory {
	if b := static.Box(); b != nil {
		return b.LogFactory()
	}
	return nil
}

// applyLogLevelToLiveBox поднимает/возвращает уровень фабрики уже работающего
// движка. No-op если туннель не запущен (новый box возьмёт уровень из своего
// конфига — сознательно НЕ навязываем ему персистентный static-уровень: именно
// «trace пережил реконнект из отравленной БД» устроил jetsam-инцидент 4.7.30 на
// iOS). Неизвестная строка уровня — no-op: лучше остаться на конфигурационном
// уровне, чем молча свалиться в trace (ParseLevel при ошибке возвращает
// LevelTrace).
//
// SetLevel пишет int-поле фабрики без синхронизации с читающими его логгерами —
// та же benign-race модель, что у static.logLevel (пишется в
// ChangeInhiveSettings под changeSettingsMu, читается lock-free в Log()).
func applyLogLevelToLiveBox(levelStr string) {
	lvl, err := log.ParseLevel(levelStr)
	if err != nil {
		return
	}
	f := liveBoxLogFactory()
	if f == nil {
		return
	}
	f.SetLevel(lvl)
	Log(LogLevel_INFO, LogType_CORE, "log level of running engine set to ", levelStr)
}
