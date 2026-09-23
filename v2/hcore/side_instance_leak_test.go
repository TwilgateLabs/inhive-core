package hcore

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
)

// TestSideInstanceCycles_NoGoroutineLeak — гард longrun-аудита 2026-09-23 §3.1:
// каждый side-instance (холодный пинг UrlTestConfig → RunInstanceRaw,
// BootstrapFetch) создаёт daemon.StartedService, а тот в конструкторе поднимает
// 5 observer-горутин. До фикса hcore звал только CloseService() (гасит box) и
// никогда Close() — горутины жили до смерти процесса, +5 на КАЖДЫЙ пинг.
//
// Свойство, а не исход: N полных циклов «поднять → закрыть» не меняют число
// горутин больше чем на константу, независимую от N. На старом коде рост
// линейный (5×N), порог ниже этого.
func TestSideInstanceCycles_NoGoroutineLeak(t *testing.T) {
	const cycles = 5
	// Допуск на фоновый шум рантайма/тестового бинаря; заведомо меньше 5×cycles.
	const slack = 8

	cycle := func() {
		t.Helper()
		opts := &option.Options{
			Outbounds: []option.Outbound{{Type: "direct", Tag: "leak-probe"}},
		}
		inst, err := RunInstanceRaw(context.Background(), opts)
		if err != nil {
			t.Fatalf("side-instance bring-up: %v", err)
		}
		if err := inst.Close(); err != nil {
			t.Fatalf("side-instance close: %v", err)
		}
	}

	// Прогрев: ленивые глобалы (пулы, таймеры рантайма, init-горутины пакетов)
	// не должны засчитываться в утечку.
	cycle()
	baseline := settledGoroutines(0, 500*time.Millisecond)

	for i := 0; i < cycles; i++ {
		cycle()
	}

	after := settledGoroutines(baseline+slack, 3*time.Second)
	if after > baseline+slack {
		t.Fatalf("goroutines grew %d -> %d over %d side-instance cycles (limit +%d): StartedService.Close not called?",
			baseline, after, cycles, slack)
	}
	t.Logf("goroutines: baseline=%d after %d cycles=%d", baseline, cycles, after)
}

// settledGoroutines ждёт, пока завершающиеся горутины действительно выйдут:
// опрашивает runtime.NumGoroutine до target (или до таймаута) и возвращает
// последнее значение. target=0 — просто дать рантайму устаканиться.
func settledGoroutines(target int, timeout time.Duration) int {
	deadline := time.Now().Add(timeout)
	for {
		runtime.GC()
		runtime.Gosched()
		time.Sleep(50 * time.Millisecond)
		n := runtime.NumGoroutine()
		if (target > 0 && n <= target) || time.Now().After(deadline) {
			return n
		}
	}
}
