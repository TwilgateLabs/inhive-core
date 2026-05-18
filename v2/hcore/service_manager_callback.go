// service_manager_callback.go — lifecycle hooks for pre/post service events.
package hcore

import (
	"github.com/twilgate/inhive-core/v2/service_manager"
	"github.com/sagernet/sing-box/adapter"
)

type inhiveMainServiceManager struct{}

var _ adapter.LifecycleService = (*inhiveMainServiceManager)(nil)

func (h *inhiveMainServiceManager) Name() string { return "inhiveMainServiceManager" }
func (h *inhiveMainServiceManager) Start(stage adapter.StartStage) error {
	if stage == adapter.StartStateStarted {
		return service_manager.OnMainServiceStart()
	}
	return nil
}

func (h *inhiveMainServiceManager) Close() error {
	return service_manager.OnMainServiceClose()
}
