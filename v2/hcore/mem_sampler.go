// mem_sampler.go — лёгкий read-only сэмплер памяти ядра в лог.
//
// Зачем: на iPhone Никита видит логи ядра через gRPC-стрим (Flutter LogsPage),
// но НЕ видит память процесса без Xcode. В инциденте 2026-06-25 ядро упёрлось
// в iOS memory-limit и встало в GC death-spiral — заметить это заранее было
// нечем. Сэмплер раз в ~10с печатает компактную строку с памятью прямо в тот же
// лог, так что деградацию (рост phys_footprint / goroutines) видно на устройстве.
//
// Решение: запускать ВСЕГДА (не только под iOS memory-limit). Стоит копейки —
// один тикер раз в 10с, read-only чтение runtime/metrics + одно task_info на
// darwin — а пользу даёт на всех платформах (Windows/Android тоже полезно для
// диагностики утечек). Привязан к box-контексту и явно гасится в Stop(), горутина
// не течёт. Паттерн lifecycle зеркалит startModeWatcher/stopModeWatcher.
package hcore

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	runtimeDebug "runtime/debug"
	"runtime/metrics"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box/experimental/libbox"
	xhttp "github.com/sagernet/sing-box/transport/v2rayxhttp"
	"github.com/twilgate/inhive-core/v2/config"
)

// memSamplerInterval — период сэмплирования. 10с: достаточно часто чтобы
// поймать тренд роста памяти за минуты до упора в лимит, достаточно редко
// чтобы сам лог не стал шумом.
const memSamplerInterval = 10 * time.Second

// Диагностика jetsam-инцидента 2026-07-14 (iPhone Никиты: NE рос ~30→50MB за
// час обычного трафика и убивался per-process-limit). Три инструмента:
//   - каждый 6-й тик (60с) строка сэмпла дублируется в persistent-файл
//     <group>/Library/Caches/inhive-diag/mem.log — переживает смерть NE и
//     ЧИТАЕТСЯ с мака (devicectl пускает только в Library/Documents/tmp
//     группового контейнера, потому Caches, а не workingDir);
//   - при phys_footprint > memDiagProfileAtBytes — одноразовый дамп heap- и
//     goroutine-профилей туда же (go tool pprof назовёт утечку поимённо);
//   - каждый 12-й тик (120с) + при footprint > memFreeOSAtBytes —
//     runtimeDebug.FreeOSMemory(): jetsam считает phys_footprint, а Go-scavenger
//     отдаёт освобождённые страницы ОС лениво (разово это уже делает start.go
//     после старта — здесь периодически). Гейт iOS/Android как в start.go.
const (
	memDiagFileMaxBytes   = 512 * 1024
	memDiagProfileAtBytes = 42 << 20
	memFreeOSAtBytes      = 40 << 20
)

// memDiagDir возвращает каталог диагностики (создавая его) или "" если
// недоступен. iOS-only: на остальных платформах достаточно лог-стрима.
func memDiagDir() string {
	if runtime.GOOS != "ios" || sWorkingPath == "" {
		return ""
	}
	dir := filepath.Join(sWorkingPath, "..", "Library", "Caches", "inhive-diag")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	return dir
}

// memDiagAppend дописывает строку в mem.log с грубой ротацией по размеру.
func memDiagAppend(dir, line string) {
	if dir == "" {
		return
	}
	path := filepath.Join(dir, "mem.log")
	if st, err := os.Stat(path); err == nil && st.Size() > memDiagFileMaxBytes {
		_ = os.Rename(path, filepath.Join(dir, "mem.prev.log"))
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(time.Now().Format("2006-01-02 15:04:05") + " " + line + "\n")
}

// memDiagProfiles пишет heap+goroutine профили (раз на процесс).
func memDiagProfiles(dir string) {
	if dir == "" {
		return
	}
	if hf, err := os.Create(filepath.Join(dir, "heap_high.pprof")); err == nil {
		_ = pprof.WriteHeapProfile(hf)
		hf.Close()
	}
	if gf, err := os.Create(filepath.Join(dir, "goroutine_high.pprof")); err == nil {
		_ = pprof.Lookup("goroutine").WriteTo(gf, 0)
		gf.Close()
	}
}

// startMemSampler привязывает сэмплер к box-контексту. Идемпотентно: каждый
// вызов гасит предыдущий сэмплер перед запуском нового. Зеркалит
// startModeWatcher (urltest_watcher.go).
func startMemSampler(boxCtx context.Context) {
	if boxCtx == nil {
		return
	}
	static.memSamplerMu.Lock()
	if static.memSamplerCancel != nil {
		static.memSamplerCancel()
	}
	ctx, cancel := context.WithCancel(boxCtx)
	static.memSamplerCancel = cancel
	static.memSamplerMu.Unlock()

	go runMemSampler(ctx)
}

// stopMemSampler гасит активный сэмплер. Идемпотентно.
func stopMemSampler() {
	static.memSamplerMu.Lock()
	defer static.memSamplerMu.Unlock()
	if static.memSamplerCancel != nil {
		static.memSamplerCancel()
		static.memSamplerCancel = nil
	}
}

// runMemSampler крутит тикер до отмены ctx (box-контекст / Stop). Каждый тик —
// одно чтение метрик и одна лог-строка вида:
//
//	mem: phys_footprint=NN.NMB heap=NN.NMB sys=NN.NMB goroutines=NN gc=NN
//
// phys_footprint печатается только там где доступен (darwin+cgo); на остальных
// платформах поле опускается.
func runMemSampler(ctx context.Context) {
	defer config.DeferPanicToError("memSampler", func(err error) {
		Log(LogLevel_ERROR, LogType_CORE, "memSampler panic: ", err.Error())
	})

	// runtime/metrics дешевле ReadMemStats (не делает stop-the-world и читает
	// только запрошенные сэмплы). Сэмпл-слайс переиспользуем между тиками.
	samples := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"}, // живые heap-объекты (~HeapInuse)
		{Name: "/memory/classes/total:bytes"},        // вся память от ОС (~Sys)
		{Name: "/gc/cycles/total:gc-cycles"},         // завершённых GC-циклов (~NumGC)
	}

	ticker := time.NewTicker(memSamplerInterval)
	defer ticker.Stop()

	diagDir := memDiagDir()
	tick := 0
	profileDumped := false
	var lastFreeOS time.Time
	mobile := runtime.GOOS == "ios" || runtime.GOOS == "android"

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick++
			metrics.Read(samples)
			heap := samples[0].Value.Uint64()
			sys := samples[1].Value.Uint64()
			gc := samples[2].Value.Uint64()
			goroutines := runtime.NumGoroutine()
			footprint := libbox.PhysFootprintBytes()

			line := "mem: heap=" + formatMB(heap) +
				" sys=" + formatMB(sys) +
				" goroutines=" + strconv.Itoa(goroutines) +
				" gc=" + strconv.FormatUint(gc, 10)
			if footprint > 0 {
				line = "mem: phys_footprint=" + formatMB(uint64(footprint)) +
					" heap=" + formatMB(heap) +
					" sys=" + formatMB(sys) +
					" goroutines=" + strconv.Itoa(goroutines) +
					" gc=" + strconv.FormatUint(gc, 10)
			}
			Log(LogLevel_INFO, LogType_CORE, line)

			// InHive instrumentation (TEMPORARY, see v2rayxhttp/chunkhist.go): packet-up
			// POST payload sizes as an INTERVAL snapshot, into the log stream readable on
			// Windows/Android (memDiagAppend below is iOS-only — memDiagDir returns ""
			// elsewhere — and Windows is exactly where we need it).
			//
			// Level is WARN, not INFO, on purpose: the client configures the core log
			// level as 'warn' by default (singbox_config_builder.dart `_baseLog`), so an
			// INFO line never reaches the user-visible Logs tab. goroutines are carried
			// on the same line because a goroutine count climbing in step with the decay
			// would point at leaked in-flight POSTs (PostPacket runs under
			// context.WithoutCancel with no timeout) rather than at chunk starvation.
			if postHist := xhttp.PostChunkHistogram(int64(memSamplerInterval / time.Second)); !strings.Contains(postHist, "[n=0 ") {
				lines := []string{
					postHist + " goroutines=" + strconv.Itoa(goroutines),
					xhttp.XmuxState(),
					// Счётчики отказов upload-POST'ов. Именно их отсутствие делало
					// upload-половину слепой: ошибка PostPacket нигде не логировалась
					// (см. chunkhist.go recordUploadError).
					xhttp.UploadErrorState(),
				}
				for _, l := range lines {
					Log(LogLevel_WARNING, LogType_CORE, l)
				}
				// InHive 2026-07-19: дублируем в sing-box-логгер, т.е. в data/box.log.
				//
				// Зачем: Log() выше публикует ТОЛЬКО в gRPC-поток (logproto.go —
				// static.logObserver.Publish), который виден во вкладке «Логи» в UI и
				// никогда не попадает в файл. Из-за этого снять динамику можно было
				// лишь скриншотами с устройства. box.log забирается с машины файлом,
				// поэтому диагностику нужно иметь в обоих местах.
				if f := static.CoreLogFactory; f != nil {
					xl := f.NewLogger("xhttp-diag")
					for _, l := range lines {
						xl.Warn(l)
					}
				}
			}

			if tick%6 == 0 {
				// inhive build-129: enrich the persistent diag line with the xhttp
				// write-chunk histogram to finalize the h2 write-scratch cap from
				// real device data (see v2rayxhttp/chunkhist.go). Diag-file only —
				// keeps the gRPC log stream clean. Remove with the instrumentation.
				memDiagAppend(diagDir, line+" "+xhttp.ChunkSizeHistogram())
			}

			// Профили один раз при подходе к лимиту — пока процесс ещё жив.
			if !profileDumped && footprint > memDiagProfileAtBytes {
				profileDumped = true
				memDiagProfiles(diagDir)
				memDiagAppend(diagDir, "profiles dumped at "+formatMB(uint64(footprint)))
				Log(LogLevel_WARNING, LogType_CORE,
					"mem: high-water ", formatMB(uint64(footprint)), " — heap/goroutine profiles dumped")
			}

			// Периодический возврат страниц ОС (jetsam считает phys_footprint).
			if mobile && (tick%12 == 0 ||
				(footprint > memFreeOSAtBytes && time.Since(lastFreeOS) > time.Minute)) {
				lastFreeOS = time.Now()
				runtimeDebug.FreeOSMemory()
			}
		}
	}
}

// formatMB форматирует байты как "NN.NMB" — компактно для одной лог-строки.
func formatMB(b uint64) string {
	mb := float64(b) / (1024 * 1024)
	return strconv.FormatFloat(mb, 'f', 1, 64) + "MB"
}
