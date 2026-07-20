package hcore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetCoreLog возвращает синглтон в исходное состояние и восстанавливает его
// после теста (тесты пакета делят процесс). Поля копируются поимённо — сам
// coreLogWriter содержит мьютекс, копировать структуру целиком нельзя.
func resetCoreLog(t *testing.T) {
	t.Helper()
	coreLog.mu.Lock()
	prevFile, prevSize, prevPath, prevBacklog :=
		coreLog.file, coreLog.size, coreLog.path, coreLog.backlog
	coreLog.file = nil
	coreLog.size = 0
	coreLog.path = ""
	coreLog.backlog = nil
	coreLog.mu.Unlock()
	prevMax := coreLogMaxBytes
	t.Cleanup(func() {
		coreLog.mu.Lock()
		if coreLog.file != nil {
			_ = coreLog.file.Close()
		}
		coreLog.file, coreLog.size, coreLog.path, coreLog.backlog =
			prevFile, prevSize, prevPath, prevBacklog
		coreLog.mu.Unlock()
		coreLogMaxBytes = prevMax
	})
}

// Пункт 3 волны логов 2026-07-21: события hcore.Log обязаны переживать смерть
// процесса — раньше жили только в gRPC-стриме. Строки до initCoreLog (ранний
// Setup) копятся в backlog и выливаются в файл при инициализации.
func TestCoreLog_BacklogFlushedOnInit(t *testing.T) {
	resetCoreLog(t)
	dir := t.TempDir()

	coreLogAppend(LogLevel_WARNING, LogType_CORE, "early line before setup")
	initCoreLog(dir)
	coreLogAppend(LogLevel_ERROR, LogType_CORE, "late line after setup")

	data, err := os.ReadFile(filepath.Join(dir, "core.log"))
	if err != nil {
		t.Fatalf("core.log not created: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "early line before setup") {
		t.Errorf("backlog line lost:\n%s", text)
	}
	if !strings.Contains(text, "late line after setup") {
		t.Errorf("direct line lost:\n%s", text)
	}
	if strings.Index(text, "early") > strings.Index(text, "late") {
		t.Errorf("backlog must precede direct writes:\n%s", text)
	}
	if !strings.Contains(text, "WARNING") || !strings.Contains(text, "ERROR") {
		t.Errorf("level names missing:\n%s", text)
	}
}

// Гейт уровня — тот же, что у стрима: что не прошло static.logLevel, того нет
// и в файле (иначе warn-режим писал бы на диск каждый trace движка).
func TestCoreLog_RespectsStreamLevelGate(t *testing.T) {
	resetCoreLog(t)
	prevLevel := static.logLevel
	defer func() { static.logLevel = prevLevel }()
	dir := t.TempDir()
	initCoreLog(dir)

	static.logLevel = LogLevel_WARNING
	Log(LogLevel_DEBUG, LogType_CORE, "filtered debug line")
	Log(LogLevel_WARNING, LogType_CORE, "passing warn line")

	data, err := os.ReadFile(filepath.Join(dir, "core.log"))
	if err != nil {
		t.Fatalf("core.log not created: %v", err)
	}
	if strings.Contains(string(data), "filtered debug line") {
		t.Errorf("line below static.logLevel reached file")
	}
	if !strings.Contains(string(data), "passing warn line") {
		t.Errorf("line at static.logLevel missing from file")
	}
}

// Ротация: при переполнении файл уезжает в core.log.1, новый начинается с
// нуля — на диске не больше двух капов (иначе многочасовая trace-сессия
// раздула бы файл бесконечно).
func TestCoreLog_RotatesAtCap(t *testing.T) {
	resetCoreLog(t)
	coreLogMaxBytes = 256
	dir := t.TempDir()
	initCoreLog(dir)

	for i := 0; i < 20; i++ {
		coreLogAppend(LogLevel_WARNING, LogType_CORE, "padding line to overflow the tiny cap")
	}

	main, err := os.Stat(filepath.Join(dir, "core.log"))
	if err != nil {
		t.Fatalf("core.log missing after rotation: %v", err)
	}
	if main.Size() > 2*coreLogMaxBytes {
		t.Errorf("core.log size %d exceeds cap %d", main.Size(), coreLogMaxBytes)
	}
	if _, err := os.Stat(filepath.Join(dir, "core.log.1")); err != nil {
		t.Errorf("core.log.1 backup missing: %v", err)
	}
}

// Переросший с прошлого запуска файл ротируется при initCoreLog (иначе
// кап действовал бы только внутри одной сессии).
func TestCoreLog_RotatesOversizedOnInit(t *testing.T) {
	resetCoreLog(t)
	coreLogMaxBytes = 64
	dir := t.TempDir()
	path := filepath.Join(dir, "core.log")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 200)), 0o644); err != nil {
		t.Fatal(err)
	}

	initCoreLog(dir)
	coreLogAppend(LogLevel_WARNING, LogType_CORE, "fresh")

	backup, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("oversized file not rotated on init: %v", err)
	}
	if len(backup) != 200 {
		t.Errorf("backup size = %d, want 200", len(backup))
	}
	fresh, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(fresh), "fresh") || strings.Contains(string(fresh), "xxx") {
		t.Errorf("new file must contain only fresh lines:\n%s", string(fresh))
	}
}
