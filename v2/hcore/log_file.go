// log_file.go — персистентный core.log: файловая копия всего, что hcore.Log
// отдаёт в gRPC-стрим вкладки «Логи».
//
// Зачем: hcore.Log писал ТОЛЬКО в broadcaster (история 200 строк в памяти).
// Всё, что случилось до подписки UI на стрим или после его смерти —
// ошибки Setup, падение процесса, события «шторка-старта» на iOS без
// приложения — терялось безвозвратно. Логи существуют, чтобы юзер прислал их
// в поддержку ⇒ у стрима обязан быть файловый след. core.log лежит рядом с
// остальным пост-мортемом (<workingDir>/data/, там же stderr*.log и
// heartbeat) и попадает в экспорт диагностики отдельной секцией.
//
// Что попадает: ровно то, что прошло гейт static.logLevel — то есть то, что
// увидела бы вкладка. Движковые строки, идущие через PlatformWriter
// (LogType_SERVICE), здесь тоже есть: box.log их режет уровнем фабрики, а
// ошибки самого StartedService (WriteMessage(LevelError, ...) в daemon) мимо
// фабрики и в box.log не попадают вовсе.
//
// Ротация — по образцу box.log (sing-box/log/observable.go): при переполнении
// файл переименовывается в core.log.1 (одна бэкап-копия, перезаписывая
// старую) и открывается заново. Максимум на диске: 2 × coreLogMaxBytes.
package hcore

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// coreLogMaxBytes — порог ротации. Переменная, а не константа — тесты
// уменьшают, чтобы проверить ротацию без записи мегабайтов.
var coreLogMaxBytes = int64(5 * 1024 * 1024)

// coreLogBacklogCap — сколько строк держим в памяти до initCoreLog (Setup ещё
// не сообщил workingDir). Ранние строки Setup'а исчисляются десятками;
// 200 — с запасом и симметрично истории logObserver.
const coreLogBacklogCap = 200

type coreLogWriter struct {
	mu      sync.Mutex
	file    *os.File
	size    int64
	path    string
	backlog []string
}

var coreLog = &coreLogWriter{}

// initCoreLog открывает <dir>/core.log (создавая каталог), ротирует
// переросший файл и сливает накопленный до инициализации backlog. Ошибки
// проглатываются: диагностический файл не имеет права ронять Setup ядра.
// Повторный вызов с тем же каталогом (повторный Setup на Android reconnect) —
// no-op.
func initCoreLog(dir string) {
	coreLog.mu.Lock()
	defer coreLog.mu.Unlock()

	path := filepath.Join(dir, "core.log")
	if coreLog.file != nil && coreLog.path == path {
		return
	}
	if coreLog.file != nil {
		_ = coreLog.file.Close()
		coreLog.file = nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	if st, err := os.Stat(path); err == nil && st.Size() > coreLogMaxBytes {
		_ = os.Rename(path, path+".1")
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	coreLog.file = f
	coreLog.path = path
	if st, err := f.Stat(); err == nil {
		coreLog.size = st.Size()
	} else {
		coreLog.size = 0
	}
	for _, line := range coreLog.backlog {
		coreLog.writeLocked(line)
	}
	coreLog.backlog = nil
}

// coreLogAppend форматирует и дописывает строку. До initCoreLog строки
// копятся в backlog (ранний Setup), после — пишутся сразу.
func coreLogAppend(level LogLevel, typ LogType, msg string) {
	line := fmt.Sprintf("[%s] %-7s %-7s %s\n",
		time.Now().Format("2006-01-02 15:04:05.000"),
		level.String(), typ.String(), msg)

	coreLog.mu.Lock()
	defer coreLog.mu.Unlock()
	if coreLog.file == nil {
		if len(coreLog.backlog) < coreLogBacklogCap {
			coreLog.backlog = append(coreLog.backlog, line)
		}
		return
	}
	coreLog.writeLocked(line)
}

// writeLocked пишет строку и ротирует при переполнении. Вызывать только под
// coreLog.mu и с открытым file.
func (w *coreLogWriter) writeLocked(line string) {
	n, err := w.file.WriteString(line)
	if err != nil {
		return
	}
	w.size += int64(n)
	if w.size <= coreLogMaxBytes {
		return
	}
	_ = w.file.Close()
	w.file = nil
	_ = os.Rename(w.path, w.path+".1")
	f, err := os.OpenFile(w.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return // следующий initCoreLog переоткроет; строки до него уйдут в backlog
	}
	w.file = f
	w.size = 0
}
