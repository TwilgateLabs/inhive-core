package service_manager

import (
	"github.com/sagernet/sing-box/option"
)

// Регистраторов нет: Register / RegisterPreService снесены 2026-09-23 (0 вызовов
// в core и app — наследие hiddify-расширений). Списки ниже всегда пусты, так что
// хуки Start/Dispose/OnMainService* сейчас no-op. Пакет держится только ради
// этих вызовов из hcore; снос целиком — отдельным заходом.
var (
	services    = []HService{}
	preservices = []HService{}
)

func StartServices() error {
	DisposeServices()
	for _, service := range preservices {
		if err := service.Init(); err != nil {
			return err
		}
	}
	for _, service := range services {
		if err := service.Init(); err != nil {
			return err
		}
	}
	return nil
}

func DisposeServices() error {
	for _, service := range services {
		if err := service.Dispose(); err != nil {
			return err
		}
	}
	for _, service := range preservices {
		if err := service.Dispose(); err != nil {
			return err
		}
	}
	return nil
}

func OnMainServicePreStart(singconfig *option.Options) error {
	for _, service := range preservices {
		if err := service.OnMainServicePreStart(singconfig); err != nil {
			return err
		}
	}
	for _, service := range services {
		if err := service.OnMainServicePreStart(singconfig); err != nil {
			return err
		}
	}
	return nil
}

func OnMainServiceStart() error {
	for _, service := range preservices {
		if err := service.OnMainServiceStart(); err != nil {
			return err
		}
	}
	for _, service := range services {
		if err := service.OnMainServiceStart(); err != nil {
			return err
		}
	}
	return nil
}

func OnMainServiceClose() error {
	for _, service := range preservices {
		if err := service.OnMainServiceClose(); err != nil {
			return err
		}
	}
	for _, service := range services {
		if err := service.OnMainServiceClose(); err != nil {
			return err
		}
	}
	return nil
}
