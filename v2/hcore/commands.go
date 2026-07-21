// commands.go — gRPC handlers: system info, outbound selection, URL testing.
package hcore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/protocol/group"
	"github.com/twilgate/inhive-core/v2/config"
	hcommon "github.com/twilgate/inhive-core/v2/hcommon"

	"github.com/sagernet/sing-box/common/monitoring"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/memory"
	"google.golang.org/grpc"
)

func (h *InhiveInstance) readStatus(prev *SystemInfo) *SystemInfo {
	var message SystemInfo
	message.Memory = int64(memory.Inuse())
	message.Goroutines = int32(runtime.NumGoroutine())

	if ss := h.StartedService; ss != nil {
		status := ss.ReadStatus()
		message.DownlinkTotal = status.DownlinkTotal
		message.UplinkTotal = status.UplinkTotal
		message.ConnectionsIn = status.ConnectionsIn
		message.ConnectionsOut = status.ConnectionsOut

		if prev != nil {
			message.Uplink = message.UplinkTotal - prev.UplinkTotal
			message.Downlink = message.DownlinkTotal - prev.DownlinkTotal
		}
		if box := h.Box(); box != nil {
			current := ""
			if currentOutBound, ok := box.Outbound().Outbound(config.OutboundSelectTag); ok {
				if selectOutBound, ok := currentOutBound.(*group.Selector); ok {
					current = selectOutBound.Now()
					message.CurrentOutbound = TrimTagName(current)
				}
			}
			if currentOutBound, ok := box.Outbound().Outbound(current); ok {
				if g, ok := currentOutBound.(adapter.OutboundGroup); ok {
					if now := g.Now(); now != "" {
						message.CurrentOutbound = fmt.Sprint(message.CurrentOutbound, "→", TrimTagName(now))
					}
				}
			}
		}

		if prev == nil || prev.CurrentProfile == "" || message.UplinkTotal < 1000000 {
			// Кеш вместо db.Get: этот метод тикает 1/сек из
			// GetSystemInfoStream, а goleveldb open/close на каждый тик —
			// alloc-churn под 32MB memory-limit iOS NE (см. start.go,
			// cachedLastStartRequestName).
			message.CurrentProfile = cachedLastStartRequestName()
		} else {
			message.CurrentProfile = prev.CurrentProfile
		}
	}

	return &message
}

func (s *CoreService) GetSystemInfo(ctx context.Context, req *hcommon.Empty) (resp *SystemInfo, err error) {
	return static.readStatus(nil), nil

}
func (s *CoreService) GetSystemInfoStream(req *hcommon.Empty, stream grpc.ServerStreamingServer[SystemInfo]) (err error) {
	return static.GetSystemInfo(stream)

}
func (h *InhiveInstance) MakeSureContextIsNew(streamContext context.Context) {
	for range 10 {
		if ctx := h.Context(); ctx != nil {
			select {
			case <-ctx.Done(): //if old context is done waiting for new context
			default:
				return
			}
		}
		select {
		case <-streamContext.Done():
			return
		case <-time.After(time.Millisecond * 500):
		}
	}
}
func (h *InhiveInstance) GetSystemInfo(stream grpc.ServerStreamingServer[SystemInfo]) error {
	h.MakeSureContextIsNew(stream.Context())

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()

	ctx := h.Context()
	if ctx == nil {
		return E.New("service not ready")
	}
	current_status := h.readStatus(nil)
	if err := stream.Send(current_status); err != nil {
		Log(LogLevel_ERROR, LogType_CORE, "send System Info failed", err)
	}
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			current_status = h.readStatus(current_status)
			if err := stream.Send(current_status); err != nil {
				Log(LogLevel_ERROR, LogType_CORE, "send System Info failed", err)
			}
		}
	}

}

func (s *CoreService) SelectOutbound(ctx context.Context, in *SelectOutboundRequest) (resp *hcommon.Response, err error) {
	defer config.RecoverPanicToError("CoreService.SelectOutbound", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp = &hcommon.Response{Code: hcommon.ResponseCode_FAILED, Message: e.Error()}
		err = e
	})
	return static.SelectOutbound(in)
}

func (h *InhiveInstance) SelectOutbound(in *SelectOutboundRequest) (*hcommon.Response, error) {
	Log(LogLevel_DEBUG, LogType_CORE, "select outbound: ", in.GroupTag, " -> ", in.OutboundTag)
	if box := h.Box(); box != nil {
		outboundGroup, isLoaded := box.Outbound().Outbound(in.GroupTag)
		if !isLoaded {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("selector not found: ", in.GroupTag).Error(),
			}, E.New("selector not found: ", in.GroupTag)
		}
		selector, isSelector := outboundGroup.(*group.Selector)
		if !isSelector {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("outbound is not a selector: ", in.GroupTag).Error(),
			}, E.New("outbound is not a selector: ", in.GroupTag)
		}
		if !selector.SelectOutbound(in.OutboundTag) {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("outbound not found in selector:: ", in.GroupTag).Error(),
			}, E.New("outbound not found in selector: ", in.GroupTag)
		}
		Log(LogLevel_DEBUG, LogType_CORE, "Trying to ping outbound: ", in.OutboundTag)
	}
	return &hcommon.Response{
		Code:    hcommon.ResponseCode_OK,
		Message: "",
	}, nil
}

// ── Hot-add (2026-07-19) ────────────────────────────────────────────────────
//
// Динамическое добавление/удаление outbound'ов в ЖИВОЙ box без рестарта.
// Мотивация: кросс-подписочный dual-tunnel (клиент выбирает сервер, которого
// нет в активном конфиге) раньше требовал полной пересборки box = разрыв всех
// соединений. OutboundManager.Create/Remove апстрима уже умеют started-режим
// (manager.go: LegacyStart всех стадий при started), router и clash API
// резолвят по тегу лениво; блокером было только статичное членство Selector —
// закрыто AddMember/RemoveMember (protocol/group/selector.go, наш форк).

func (s *CoreService) AddOutbound(ctx context.Context, in *AddOutboundRequest) (resp *AddOutboundResponse, err error) {
	defer config.RecoverPanicToError("CoreService.AddOutbound", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp = &AddOutboundResponse{}
		err = e
	})
	return static.AddOutbound(in)
}

func (h *InhiveInstance) AddOutbound(in *AddOutboundRequest) (*AddOutboundResponse, error) {
	box := h.Box()
	if box == nil {
		return nil, E.New("add outbound: core not started")
	}
	// Тот же парс-пайплайн, что у Parse RPC: share-link ИЛИ sing-box JSON
	// (одиночный outbound-объект оборачивается в outbounds:[...] внутри,
	// endpoint-типа — в endpoints:[...]; см. config.parseSingboxJSON).
	opts, parseErr := config.ParseConfig(h.Context(), &config.ReadOptions{Content: in.Content}, true, static.InhiveOptions, false)
	if parseErr != nil {
		return nil, E.Cause(parseErr, "add outbound: parse")
	}
	// Берём только «настоящие» серверные outbound'ы: парсер может дописать
	// служебные (selector/urltest/direct/block/dns) — их в живой box не тащим.
	systemTypes := map[string]bool{
		"selector": true, "urltest": true, "direct": true, "block": true, "dns": true,
	}
	var real []int
	for i := range opts.Outbounds {
		if !systemTypes[opts.Outbounds[i].Type] {
			real = append(real, i)
		}
	}
	if len(real) == 0 && len(opts.Endpoints) == 0 {
		return nil, E.New("add outbound: no usable outbound in content")
	}
	// Главный (его тег идёт в селекторы и в ответ) — первый «настоящий»
	// outbound, а если их нет — первый endpoint (wireguard/awg: sing-box 1.13+
	// держит их в endpoints[], создаются через EndpointManager; в селекторе они
	// полноправные члены — adapter.Endpoint реализует adapter.Outbound, а
	// OutboundManager.Outbound(tag) резолвит endpoint-теги fallback'ом).
	// Остальные (helper'ы вида utproto-пары с detour) создаются как есть.
	mainIsEndpoint := len(real) == 0
	var mainTag string
	if mainIsEndpoint {
		if in.TagOverride != "" {
			opts.Endpoints[0].Tag = in.TagOverride
		}
		mainTag = opts.Endpoints[0].Tag
	} else {
		if in.TagOverride != "" {
			opts.Outbounds[real[0]].Tag = in.TagOverride
		}
		mainTag = opts.Outbounds[real[0]].Tag
	}
	logFactory := h.CoreLogFactory
	if logFactory == nil {
		logFactory = log.NewNOPFactory()
	}
	for _, i := range real {
		ob := opts.Outbounds[i]
		createErr := box.Outbound().Create(
			h.Context(),
			box.Router(),
			logFactory.NewLogger("outbound/hotadd["+ob.Tag+"]"),
			ob.Tag,
			ob.Type,
			ob.Options,
		)
		if createErr != nil {
			return nil, E.Cause(createErr, "add outbound: create ", ob.Tag)
		}
	}
	for i := range opts.Endpoints {
		ep := opts.Endpoints[i]
		createErr := box.Endpoint().Create(
			h.Context(),
			box.Router(),
			logFactory.NewLogger("endpoint/hotadd["+ep.Tag+"]"),
			ep.Tag,
			ep.Type,
			ep.Options,
		)
		if createErr != nil {
			return nil, E.Cause(createErr, "add outbound: create endpoint ", ep.Tag)
		}
	}
	created, loaded := box.Outbound().Outbound(mainTag)
	if !loaded {
		return nil, E.New("add outbound: created outbound vanished: ", mainTag)
	}
	for _, selectorTag := range in.SelectorTags {
		groupOutbound, isLoaded := box.Outbound().Outbound(selectorTag)
		if !isLoaded {
			return nil, E.New("add outbound: selector not found: ", selectorTag)
		}
		selector, isSelector := groupOutbound.(*group.Selector)
		if !isSelector {
			return nil, E.New("add outbound: not a selector: ", selectorTag)
		}
		selector.AddMember(mainTag, created)
	}
	Log(LogLevel_INFO, LogType_CORE, "hot-add outbound: ", mainTag,
		" -> selectors ", fmt.Sprint(in.SelectorTags))
	return &AddOutboundResponse{OutboundTag: mainTag}, nil
}

func (s *CoreService) RemoveOutbound(ctx context.Context, in *RemoveOutboundRequest) (resp *hcommon.Response, err error) {
	defer config.RecoverPanicToError("CoreService.RemoveOutbound", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp = &hcommon.Response{Code: hcommon.ResponseCode_FAILED, Message: e.Error()}
		err = e
	})
	return static.RemoveOutbound(in)
}

func (h *InhiveInstance) RemoveOutbound(in *RemoveOutboundRequest) (*hcommon.Response, error) {
	box := h.Box()
	if box == nil {
		return nil, E.New("remove outbound: core not started")
	}
	// Порядок обязателен: сперва членство во ВСЕХ селекторах (RemoveMember
	// переводит selected на default/первый и interrupt'ит соединения), потом
	// manager.Remove — иначе selected селектора держит закрытый outbound.
	for _, ob := range box.Outbound().Outbounds() {
		if selector, isSelector := ob.(*group.Selector); isSelector {
			selector.RemoveMember(in.OutboundTag)
		}
	}
	removeErr := box.Outbound().Remove(in.OutboundTag)
	if errors.Is(removeErr, os.ErrInvalid) {
		// Не найден среди outbound'ов — hot-added wireguard/awg живёт в
		// EndpointManager (оба менеджера возвращают os.ErrInvalid на незнакомый
		// тег). Симметрия к AddOutbound, который создаёт endpoint'ы там же.
		removeErr = box.Endpoint().Remove(in.OutboundTag)
	}
	if removeErr != nil {
		return &hcommon.Response{
			Code:    hcommon.ResponseCode_FAILED,
			Message: removeErr.Error(),
		}, removeErr
	}
	Log(LogLevel_INFO, LogType_CORE, "hot-remove outbound: ", in.OutboundTag)
	return &hcommon.Response{Code: hcommon.ResponseCode_OK}, nil
}

func (s *CoreService) UrlTest(ctx context.Context, in *UrlTestRequest) (resp *hcommon.Response, err error) {
	defer config.RecoverPanicToError("CoreService.UrlTest", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp = &hcommon.Response{Code: hcommon.ResponseCode_FAILED, Message: e.Error()}
		err = e
	})
	return static.UrlTest(in)
}

func (s *CoreService) UrlTestActive(ctx context.Context, in *hcommon.Empty) (resp *hcommon.Response, err error) {
	defer config.RecoverPanicToError("CoreService.UrlTestActive", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp = &hcommon.Response{Code: hcommon.ResponseCode_FAILED, Message: e.Error()}
		err = e
	})

	return static.UrlTestActive()
}

func (h *InhiveInstance) UrlTestActive() (*hcommon.Response, error) {
	if box := h.Box(); box != nil {
		outboundGroup, isLoaded := box.Outbound().Outbound(config.OutboundSelectTag)
		if !isLoaded {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("selector not found: ", config.OutboundSelectTag).Error(),
			}, E.New("selector not found: ", config.OutboundSelectTag)
		}
		selector, isSelector := outboundGroup.(adapter.OutboundGroup)
		if !isSelector {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("outbound is not a selector: ", config.OutboundSelectTag).Error(),
			}, E.New("outbound is not a selector: ", config.OutboundSelectTag)
		}
		now := selector.Now()
		if now == "" {
			return &hcommon.Response{
				Code:    hcommon.ResponseCode_FAILED,
				Message: E.New("outbound not found in selector: ", config.OutboundSelectTag).Error(),
			}, E.New("outbound not found in selector: ", config.OutboundSelectTag)
		}
		if outboundGroupInner, isLoaded := box.Outbound().Outbound(now); isLoaded {
			if grp, isgrp := outboundGroupInner.(adapter.OutboundGroup); isgrp {
				if n2 := grp.Now(); n2 != "" {
					now = n2
				}
			}

		}
		return h.UrlTest(&UrlTestRequest{
			Tag: now,
		})

	}
	return &hcommon.Response{
		Code:    hcommon.ResponseCode_OK,
		Message: "",
	}, nil
}

func (h *InhiveInstance) UrlTest(in *UrlTestRequest) (*hcommon.Response, error) {
	if in.Tag == "" {
		return h.UrlTestActive()
	}
	box := h.Box()
	if box == nil {
		return nil, E.New("service not ready")
	}
	monitor := monitoring.Get(h.Context())
	monitor.TestNow(in.Tag)
	return &hcommon.Response{
		Code:    hcommon.ResponseCode_OK,
		Message: "",
	}, nil
}

// SwitchMode records the new desired mode and broadcasts an ack on the
// ModeStateListener stream. It deliberately does NOT stop or reconfigure
// the running sing-box service: a Mode-1↔Mode-2 transition is implemented
// in the main app as an NE Provider restart with a different
// providerConfiguration, which is the only way to actually unload the
// previous data plane from RAM (relevant for the iOS 15 MB jetsam budget).
//
// Validation: mode must be 1 or 2. Other values fail and emit an error
// event so listeners can surface the rejection.
func (s *CoreService) SwitchMode(ctx context.Context, in *SwitchModeRequest) (resp *hcommon.Response, err error) {
	defer config.RecoverPanicToError("CoreService.SwitchMode", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp = &hcommon.Response{Code: hcommon.ResponseCode_FAILED, Message: e.Error()}
		err = e
	})
	return static.SwitchMode(in)
}

func (h *InhiveInstance) SwitchMode(in *SwitchModeRequest) (*hcommon.Response, error) {
	if in == nil {
		err := E.New("SwitchMode: nil request")
		emitModeState(0, err.Error(), "")
		return &hcommon.Response{Code: hcommon.ResponseCode_FAILED, Message: err.Error()}, err
	}
	switch in.Mode {
	case 1, 2:
		// ok
	default:
		err := E.New("SwitchMode: invalid mode ", in.Mode, " (allowed: 1, 2)")
		emitModeState(0, err.Error(), "")
		return &hcommon.Response{Code: hcommon.ResponseCode_FAILED, Message: err.Error()}, err
	}
	previous := static.currentMode.Swap(in.Mode)
	Log(LogLevel_DEBUG, LogType_CORE, "SwitchMode: ", previous, " -> ", in.Mode)
	emitModeState(in.Mode, "", "")
	return &hcommon.Response{Code: hcommon.ResponseCode_OK, Message: ""}, nil
}

// ModeStateListener — server-streaming endpoint. Pattern mirrors
// GetSystemInfoStream: emit a snapshot immediately, then forward events
// from the broadcaster until either the gRPC client or the daemon context
// goes away.
//
// We intentionally do NOT gate this stream on h.Context() (the sing-box
// daemon context). Mode state is meaningful even when the VPN is off
// (e.g. the main app wants to know "what mode will we boot into when the
// user toggles the switch?"), so the only termination signal is the
// client stream itself.
func (s *CoreService) ModeStateListener(req *hcommon.Empty, stream grpc.ServerStreamingServer[ModeStateResponse]) (err error) {
	defer config.RecoverPanicToError("CoreService.ModeStateListener", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		err = e
	})
	return static.ModeStateListener(stream)
}

func (h *InhiveInstance) ModeStateListener(stream grpc.ServerStreamingServer[ModeStateResponse]) error {
	if static.modeStateObserver == nil {
		return E.New("modeStateObserver not initialised")
	}
	events := static.modeStateObserver.Subscribe(8)
	// Explicit unsubscribe on client disconnect. Without this, a churn of
	// gRPC clients reconnecting (e.g. NE provider restarts during a
	// Mode-1↔2 transition) would leak subscriber slots in the broadcaster's
	// internal map. Broadcaster auto-closes on its own context cancel, but
	// that's process-lifetime — we want per-stream cleanup.
	defer static.modeStateObserver.Unsubscribe(events)

	// Initial snapshot — current desired mode, no error.
	if err := stream.Send(&ModeStateResponse{
		CurrentMode:     static.currentMode.Load(),
		Success:         true,
		TimestampMs:     time.Now().UnixMilli(),
		ActiveTransport: currentActiveTransport(),
	}); err != nil {
		Log(LogLevel_ERROR, LogType_CORE, "ModeStateListener: initial send failed: ", err.Error())
		return err
	}

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case evt, ok := <-events:
			if !ok {
				// Broadcaster closed (process shutdown).
				return nil
			}
			if evt == nil {
				continue
			}
			if err := stream.Send(evt); err != nil {
				Log(LogLevel_ERROR, LogType_CORE, "ModeStateListener: send failed: ", err.Error())
				return err
			}
		}
	}
}
