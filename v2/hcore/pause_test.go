package hcore

import (
	"testing"
	"time"
)

// Свойство гейта пробы после сна (device-дамп 2026-09-07): ПАУЗА без ЗАМОРОЗКИ
// процесса — любой длины — никогда не ведёт к проверке/сбросу соединений.
// Старый гейт (wakeResetMinPause=30 с по длине паузы) на первом же кейсе делал
// ResetNetwork и рвал живые стримы — 33 из 34 срабатываний за 41 минуту.
func TestShouldProbeAfterSleep_PauseWithoutFreezeNeverProbes(t *testing.T) {
	for _, pause := range []time.Duration{5 * time.Second, 35 * time.Second, 73 * time.Second, 10 * time.Minute, 8 * time.Hour} {
		pausedAt := time.Now()
		// Monotonic шёл всё время паузы: now = pausedAt + pause по обеим шкалам.
		now := pausedAt.Add(pause)
		wall, frozen := frozenSince(pausedAt, now)
		if wall != pause {
			t.Fatalf("pause %s: wall=%s", pause, wall)
		}
		if frozen != 0 {
			t.Fatalf("pause %s: frozen=%s, want 0", pause, frozen)
		}
		if shouldProbeAfterSleep(frozen) {
			t.Fatalf("pause %s without freeze must not probe", pause)
		}
	}
}

// Реальный сон SoC: wall-часы ушли вперёд, monotonic — нет. frozen = разница.
func TestFrozenSince_DetectsClockGap(t *testing.T) {
	pausedAt := time.Now()
	awake := 5 * time.Second
	wallGap := 3 * time.Minute
	nowWall := pausedAt.Round(0).Add(wallGap)
	nowMono := pausedAt.Add(awake)
	wall, frozen := frozenSinceParts(pausedAt, nowWall, nowMono)
	if wall != wallGap {
		t.Fatalf("wall=%s want %s", wall, wallGap)
	}
	if frozen != wallGap-awake {
		t.Fatalf("frozen=%s want %s", frozen, wallGap-awake)
	}
	if !shouldProbeAfterSleep(frozen) {
		t.Fatalf("frozen %s must probe", frozen)
	}
	if shouldProbeAfterSleep(90 * time.Second) {
		t.Fatalf("frozen 90s below threshold must not probe")
	}
	if !shouldProbeAfterSleep(wakeProbeMinFrozen) {
		t.Fatalf("frozen == threshold must probe")
	}
}

func TestFrozenSince_ClockWentBackwardsClampsToZero(t *testing.T) {
	pausedAt := time.Now()
	nowWall := pausedAt.Round(0).Add(-10 * time.Second)
	nowMono := pausedAt.Add(2 * time.Second)
	wall, frozen := frozenSinceParts(pausedAt, nowWall, nowMono)
	if wall != 0 || frozen != 0 {
		t.Fatalf("wall=%s frozen=%s, want 0/0", wall, frozen)
	}
}
