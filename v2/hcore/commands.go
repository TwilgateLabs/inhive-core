// commands.go — gRPC handlers: system info, outbound selection, URL testing.
package hcore

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/twilgate/inhive-core/v2/config"
	"github.com/twilgate/inhive-core/v2/db"
	hcommon "github.com/twilgate/inhive-core/v2/hcommon"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/protocol/group"

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
			settings := db.GetTable[hcommon.AppSettings]()
			lastName, err := settings.Get("lastStartRequestName")
			if err == nil {
				message.CurrentProfile = lastName.Value.(string)
			}
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
