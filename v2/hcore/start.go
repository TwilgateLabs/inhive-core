// start.go — starts the VPN service: config building, validation, daemon launch.
package hcore

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	runtimeDebug "runtime/debug"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/twilgate/inhive-core/v2/config"
	"github.com/twilgate/inhive-core/v2/db"
	hcommon "github.com/twilgate/inhive-core/v2/hcommon"
	service_manager "github.com/twilgate/inhive-core/v2/service_manager"
)

func (s *CoreService) Start(ctx context.Context, in *StartRequest) (resp *CoreInfoResponse, err error) {
	defer config.RecoverPanicToError("CoreService.Start", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp, err = errorWrapper(MessageType_UNEXPECTED_ERROR, e)
	})
	return Start(static.BaseContext, in)
}

func Start(ctx context.Context, in *StartRequest) (*CoreInfoResponse, error) {
	return StartService(ctx, in)
}

func (s *CoreService) StartService(ctx context.Context, in *StartRequest) (resp *CoreInfoResponse, err error) {
	defer config.RecoverPanicToError("CoreService.StartService", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp, err = errorWrapper(MessageType_UNEXPECTED_ERROR, e)
	})
	return StartService(ctx, in)
}

// Кеш lastStartRequestName. GetSystemInfoStream тикает 1/сек, и пока
// UplinkTotal < 1MB (или профиль пуст) readStatus раньше КАЖДЫЙ тик ходил в
// goleveldb (db.GetTable().Get = полный open/close: аллокации, manifest, fd) —
// секундный alloc-churn под 32MB memory-limit iOS NE. Имя меняется только в
// StartService, так что кешируем при записи; DB трогаем максимум один раз
// (холодный процесс, StartService ещё не звался), результат — включая
// негативный — запоминаем.
var (
	lastStartNameMu     sync.Mutex
	lastStartNameValue  string
	lastStartNameLoaded bool
)

func setCachedLastStartRequestName(name string) {
	lastStartNameMu.Lock()
	defer lastStartNameMu.Unlock()
	lastStartNameValue = name
	lastStartNameLoaded = true
}

// cachedLastStartRequestName возвращает имя профиля без похода в DB на каждом
// тике. Если кеш холодный (процесс рестартовал, StartService ещё не звался) —
// однократное чтение из DB; неудача тоже кешируется (negative cache), иначе
// пустая DB возвращала бы нас к churn-у каждый тик.
func cachedLastStartRequestName() string {
	lastStartNameMu.Lock()
	defer lastStartNameMu.Unlock()
	if !lastStartNameLoaded {
		lastStartNameLoaded = true
		settings := db.GetTable[hcommon.AppSettings]()
		if lastName, err := settings.Get("lastStartRequestName"); err == nil && lastName != nil {
			if v, ok := lastName.Value.(string); ok {
				lastStartNameValue = v
			}
		}
	}
	return lastStartNameValue
}

func saveLastStartRequest(in *StartRequest) error {
	if in.ConfigContent == "" && in.ConfigPath == "" {
		return nil
	}
	settings := db.GetTable[hcommon.AppSettings]()
	return settings.UpdateInsert(
		&hcommon.AppSettings{
			Id:    "lastStartRequestPath",
			Value: in.ConfigPath,
		},
		&hcommon.AppSettings{
			Id:    "lastStartRequestContent",
			Value: in.ConfigContent,
		},
		&hcommon.AppSettings{
			Id:    "lastStartRequestName",
			Value: in.ConfigName,
		},
	)
}

func loadLastStartRequestIfNeeded(in *StartRequest) (*StartRequest, error) {
	if in != nil && (in.ConfigContent != "" || in.ConfigPath != "") {
		return in, nil
	}
	settings := db.GetTable[hcommon.AppSettings]()
	lastPath, err := settings.Get("lastStartRequestPath")
	if err != nil {
		return nil, err
	}
	lastContent, err := settings.Get("lastStartRequestContent")
	if err != nil {
		return nil, err
	}

	lastName, err := settings.Get("lastStartRequestName")
	if err != nil {
		return nil, err
	}
	return &StartRequest{
		ConfigPath:    lastPath.Value.(string),
		ConfigContent: lastContent.Value.(string),
		ConfigName:    lastName.Value.(string),
	}, nil
}

func StartService(ctx context.Context, in *StartRequest) (coreResponse *CoreInfoResponse, err error) {
	defer config.DeferPanicToError("startmobile", func(recovered_err error) {
		WriteSharedLogf("StartService: PANIC %v", recovered_err)
		coreResponse, err = errorWrapper(MessageType_UNEXPECTED_ERROR, recovered_err)
	})

	// Build 33 diagnostic logging — выявляет где hang в startup chain.
	// Пишется в <workingDir>/ne_last_error.log что Swift InhiveVPNPlugin
	// читает при timeout error. См. memory/feedback_arch_ios_ne_hang.md.
	WriteSharedLog("StartService: enter")

	static.lock.Lock()
	WriteSharedLog("StartService: lock acquired")
	defer static.lock.Unlock()

	if static.CoreState != CoreStates_STOPPED {
		WriteSharedLogf("StartService: ALREADY_STARTED (state=%v)", static.CoreState)
		return &CoreInfoResponse{
			CoreState:   static.CoreState,
			MessageType: MessageType_ALREADY_STARTED,
			Message:     "instance already started",
		}, nil
	}
	SetCoreStatus(CoreStates_STARTING, MessageType_EMPTY, "")
	WriteSharedLog("StartService: state=STARTING")

	in, err = loadLastStartRequestIfNeeded(in)
	if err != nil {
		WriteSharedLogf("StartService: loadLastStartRequest failed: %v", err)
		return errorWrapper(MessageType_ERROR_BUILDING_CONFIG, err)
	}

	static.previousStartRequest = in
	// Кешируем имя профиля для readStatus (см. cachedLastStartRequestName):
	// после loadLastStartRequestIfNeeded оно заполнено и из явного запроса,
	// и из DB-восстановления.
	setCachedLastStartRequestName(in.ConfigName)
	WriteSharedLog("StartService: BuildConfig begin")
	options, err := BuildConfig(ctx, in)
	if err != nil {
		WriteSharedLogf("StartService: BuildConfig FAILED: %v", err)
		return errorWrapper(MessageType_ERROR_BUILDING_CONFIG, err)
	}
	WriteSharedLog("StartService: BuildConfig done")
	saveLastStartRequest(in)

	Log(LogLevel_DEBUG, LogType_CORE, "Main Service pre start")
	WriteSharedLog("StartService: OnMainServicePreStart begin")
	if err := service_manager.OnMainServicePreStart(options); err != nil {
		WriteSharedLogf("StartService: OnMainServicePreStart FAILED: %v", err)
		return errorWrapper(MessageType_ERROR_EXTENSION, err)
	}
	WriteSharedLog("StartService: OnMainServicePreStart done")

	currentBuildConfigPath := filepath.Join(sWorkingPath, "data/current-config.json")
	Log(LogLevel_DEBUG, LogType_CORE, "Saving config to ", currentBuildConfigPath)
	WriteSharedLogf("StartService: SaveCurrentConfig begin (%s)", currentBuildConfigPath)

	config.SaveCurrentConfig(ctx, currentBuildConfigPath, *options)
	WriteSharedLog("StartService: SaveCurrentConfig done")

	if static.debug {
		pout, err := options.MarshalJSONContext(ctx)
		if err != nil {
			return errorWrapper(MessageType_ERROR_BUILDING_CONFIG, err)
		}
		Log(LogLevel_INFO, LogType_CORE, "Current Config is:\n", string(pout))
	}
	ctx = libbox.FromContext(ctx, static.globalPlatformInterface)
	if static.globalPlatformInterface != nil {
		platformWrapper := libbox.WrapPlatformInterface(static.globalPlatformInterface)
		service.MustRegister[adapter.PlatformInterface](ctx, platformWrapper)
		WriteSharedLog("StartService: PlatformInterface registered")
	} else {
		WriteSharedLog("StartService: WARN globalPlatformInterface is nil")
	}
	Log(LogLevel_DEBUG, LogType_CORE, "Starting Service with delay ?", in.DelayStart)
	if in.DelayStart {
		WriteSharedLog("StartService: DelayStart=true, sleeping 1s")
		<-time.After(1000 * time.Millisecond)
	}

	WriteSharedLog("StartService: SetMemoryLimit begin")
	libbox.SetMemoryLimit(C.IsIos || !in.DisableMemoryLimit)
	WriteSharedLog("StartService: SetMemoryLimit done")

	// Отменяемый старт: оборачиваем ctx в startCtx и сохраняем cancel ДО
	// NewService. Блокирующий olcrtc-старт (primary awaitReady, до ~30с) идёт
	// ВНУТРИ NewService и держит static.lock; static.StartedService (со своим
	// cancel) присваивается только ПОСЛЕ возврата NewService — слишком поздно
	// чтобы прервать. Stop() дёргает abortStart() ДО lock → startCtx отменяется
	// → box ctx (дериватив) → olcrtc runCtx → awaitReady просыпается. ctx здесь =
	// static.BaseContext (долгоживущий, не request-scoped), так что startCtx живёт
	// под работающим box; на успехе НЕ отменяем — только забываем ref (clear).
	startCtx, cancelStart := context.WithCancel(ctx)
	static.setStartCancel(cancelStart)
	defer static.clearStartCancel()

	WriteSharedLog("StartService: NewService begin (sing-box engine instantiation)")
	instance, err := NewService(startCtx, *options)
	if err != nil {
		WriteSharedLogf("StartService: NewService FAILED: %v", err)
		return errorWrapper(MessageType_START_SERVICE, err)
	}
	WriteSharedLog("StartService: NewService done — engine ready")
	static.StartedService = instance
	if static.debug {
		dumpGoroutinesToFile(fmt.Sprint(sWorkingPath, "/data/goroutine-start.log"))
	}
	for inb := range options.Inbounds {
		if opts, ok := options.Inbounds[inb].Options.(option.SocksInboundOptions); ok {
			static.ListenPort = opts.ListenPort
		}
	}

	// Phase 2 mode watcher — observes Mode 1 carousel health and emits
	// Mode-2 recommendations on the ModeStateListener stream. Bound to the
	// daemon context so it dies with the engine; Stop() also cancels it
	// explicitly so we don't rely on goroutine-after-shutdown semantics.
	//
	// NE-quiescence (2026-07-19): НЕ запускаем на iOS. Причины: (1) на iOS
	// Mode-2→Mode-1 recovery всё равно не advance'ится автоматически (см.
	// urltest_watcher.go doc), т.е. watcher полу-функционален; (2) он
	// подписан на группу "" и на каждом событии зовёт OutboundsHistory("")
	// → Touch() → OutboundMonitoring-карусель НИКОГДА не уходит в idleTimeout
	// → 5-мин URLTest TLS-пробы всех outbound'ов крутятся вечно на
	// подключённом туннеле (SecTrust-шум = триггер jetsam в NE). Без watcher
	// карусель усыпляется штатно, когда UI не открыт; UI-пинги на iOS идут
	// отдельным on-demand путём (clash-delay). На iOS кросс-мод свитч всё
	// равно инициирует app (рестарт NE), не ядро.
	if boxCtx := static.Context(); boxCtx != nil {
		if !C.IsIos {
			startModeWatcher(boxCtx, static)
		}
		// Read-only сэмплер памяти в лог (mem_sampler.go) — бьётся к тому же
		// box-контексту, гаснет в Stop(). Помогает видеть память ядра на
		// устройстве без Xcode (инцидент 2026-06-25). НУЖЕН на iOS (jetsam-
		// диагностика) — вне iOS-гейта.
		startMemSampler(boxCtx)
	}

	WriteSharedLog("StartService: returning STARTED")
	resp := SetCoreStatus(CoreStates_STARTED, MessageType_EMPTY, "")

	// Мобильные платформы: сразу вернуть ОС startup-мусор (парсинг конфига,
	// компиляция rule-sets оставляют 3-8MB, которые scavenger отдаёт лениво).
	// Upstream cmd_run.go делает то же после старта; наш hcore-путь — нет.
	// Критично для iOS: jetsam смотрит на phys_footprint, а не на живой heap.
	// Гейт по runtime.GOOS — консистентно с log_shared.go / grpc_server.go.
	if runtime.GOOS == "ios" || runtime.GOOS == "android" {
		runtimeDebug.FreeOSMemory()
		WriteSharedLog("StartService: FreeOSMemory done")
	}
	return resp, nil
}
