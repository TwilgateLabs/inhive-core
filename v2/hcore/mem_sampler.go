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
	"runtime"
	"runtime/metrics"
	"strconv"
	"time"

	"github.com/twilgate/inhive-core/v2/config"
	"github.com/sagernet/sing-box/experimental/libbox"
)

// memSamplerInterval — период сэмплирования. 10с: достаточно часто чтобы
// поймать тренд роста памяти за минуты до упора в лимит, достаточно редко
// чтобы сам лог не стал шумом.
const memSamplerInterval = 10 * time.Second

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

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics.Read(samples)
			heap := samples[0].Value.Uint64()
			sys := samples[1].Value.Uint64()
			gc := samples[2].Value.Uint64()
			goroutines := runtime.NumGoroutine()

			if footprint := libbox.PhysFootprintBytes(); footprint > 0 {
				Log(LogLevel_INFO, LogType_CORE,
					"mem: phys_footprint=", formatMB(footprint),
					" heap=", formatMB(heap),
					" sys=", formatMB(sys),
					" goroutines=", goroutines,
					" gc=", gc)
			} else {
				Log(LogLevel_INFO, LogType_CORE,
					"mem: heap=", formatMB(heap),
					" sys=", formatMB(sys),
					" goroutines=", goroutines,
					" gc=", gc)
			}
		}
	}
}

// formatMB форматирует байты как "NN.NMB" — компактно для одной лог-строки.
func formatMB(b uint64) string {
	mb := float64(b) / (1024 * 1024)
	return strconv.FormatFloat(mb, 'f', 1, 64) + "MB"
}
