// start.go — starts the VPN service: config building, validation, daemon launch.
package hcore

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/twilgate/inhive-core/v2/config"
	"github.com/twilgate/inhive-core/v2/db"
	hcommon "github.com/twilgate/inhive-core/v2/hcommon"
	service_manager "github.com/twilgate/inhive-core/v2/service_manager"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
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

	WriteSharedLog("StartService: NewService begin (sing-box engine instantiation)")
	instance, err := NewService(ctx, *options)
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

	WriteSharedLog("StartService: returning STARTED")
	return SetCoreStatus(CoreStates_STARTED, MessageType_EMPTY, ""), nil
}
