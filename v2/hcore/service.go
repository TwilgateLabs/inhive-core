// service.go — creates sing-box daemon service instances.
package hcore

import (
	"context"

	box "github.com/sagernet/sing-box"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/daemon"
	"github.com/sagernet/sing-box/experimental/clashapi"
	"github.com/sagernet/sing-box/experimental/clashapi/trafficontrol"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

func NewService(ctx context.Context, options option.Options) (*daemon.StartedService, error) {
	WriteSharedLog("NewService: enter")

	logInterface := LogInterface{}
	bopts := daemon.ServiceOptions{
		Context:     ctx,
		Debug:       static.debug,
		LogMaxLines: 100,
		Handler:     &logInterface,
		// Pressure-watchdog: на iOS при критическом memory-pressure сбрасывает
		// соединения + отдаёт память ОС (shed-on-critical) ДО того как jetsam
		// прибьёт packet-tunnel. Зеркалит command_server.go:63. Эффект только
		// под darwin+cgo (iOS); на Windows/Android — no-op.
		OOMKiller: C.IsIos,
		ExtraServices: []adapter.LifecycleService{
			&inhiveMainServiceManager{},
		},
	}

	WriteSharedLog("NewService: libbox.CheckConfigOptions begin")
	err := libbox.CheckConfigOptions(&options)
	if err != nil {
		WriteSharedLogf("NewService: CheckConfigOptions FAILED: %v", err)
		return nil, err
	}
	WriteSharedLog("NewService: CheckConfigOptions done")

	WriteSharedLog("NewService: daemon.NewStartedService begin")
	instance := daemon.NewStartedService(bopts)
	WriteSharedLog("NewService: daemon.NewStartedService done")

	WriteSharedLog("NewService: StartOrReloadServiceOptions begin (sing-box engine startup, builds outbounds + TUN inbound → openTun callback)")
	if err := instance.StartOrReloadServiceOptions(options); err != nil {
		WriteSharedLogf("NewService: StartOrReloadServiceOptions FAILED: %v", err)
		return nil, err
	}
	WriteSharedLog("NewService: StartOrReloadServiceOptions done")

	WriteSharedLog("NewService: returning success")
	return instance, nil
}

func (h *InhiveInstance) UrlTestHistory() *urltest.HistoryStorage {

	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.UrlTestHistory()
}

func (h *InhiveInstance) Box() *box.Box {
	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.Box()
}

func (h *InhiveInstance) Instance() *daemon.Instance {
	ss := h.StartedService
	if ss == nil {
		return nil
	}
	return ss.Instance()

}

func (h *InhiveInstance) Context() context.Context {
	ins := h.Instance()
	if ins == nil {
		return nil
	}
	return ins.Context()
}

func (h *InhiveInstance) TrafficManager() *trafficontrol.Manager {
	if ins := h.Instance(); ins != nil {
		if s := ins.ClashServer(); s != nil {
			return s.(*clashapi.Server).TrafficManager()
		}
	}
	return nil
}
