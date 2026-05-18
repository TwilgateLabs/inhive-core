package mobile

import (
	"fmt"
	"runtime/debug"

	hcore "github.com/twilgate/inhive-core/v2/hcore"

	_ "github.com/sagernet/gomobile"
	"github.com/sagernet/sing-box/experimental/libbox"
)

type SetupOptions struct {
	BasePath        string
	WorkingDir      string
	TempDir         string
	Listen          string
	Secret          string
	Debug           bool
	Mode            int
	FixAndroidStack bool
}

func Setup(opt *SetupOptions, platformInterface libbox.PlatformInterface) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mobile.Setup panic: %v\n%s", r, string(debug.Stack()))
		}
	}()
	return hcore.Setup(&hcore.SetupRequest{
		BasePath:          opt.BasePath,
		WorkingDir:        opt.WorkingDir,
		TempDir:           opt.TempDir,
		FlutterStatusPort: 0,
		Listen:            opt.Listen,
		Debug:             opt.Debug,
		Mode:              hcore.SetupMode(opt.Mode),
		Secret:            opt.Secret,
		FixAndroidStack:   opt.FixAndroidStack,
	}, platformInterface)

	// return hcore.Start(17078)
}

func Start(configPath string, configContent string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mobile.Start panic: %v\n%s", r, string(debug.Stack()))
		}
	}()
	_, err = hcore.StartService(libbox.BaseContext(nil), &hcore.StartRequest{
		ConfigPath:    configPath,
		ConfigContent: configContent,
		// Dart-side singbox_config_builder.dart строит готовый sing-box JSON
		// напрямую — НЕ нужно rebuild через InhiveOptions builder (который на
		// iOS падал с "outbound/balancer[balance]: unknown load balance
		// strategy" из-за empty BalancerStrategy в Hiddify legacy options).
		// Win/Android тоже передают enableRawConfig=true (см.
		// lib/core/bridge.dart:start where configContent != null).
		EnableRawConfig: true,
	})
	return err
}

func Stop() (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mobile.Stop panic: %v\n%s", r, string(debug.Stack()))
		}
	}()
	_, err = hcore.Stop()
	return err
}

func GetServerPublicKey() []byte {
	defer func() {
		if r := recover(); r != nil {
			// best-effort: logging is the caller's responsibility, return nil on panic
			_ = fmt.Errorf("mobile.GetServerPublicKey panic: %v\n%s", r, string(debug.Stack()))
		}
	}()
	return hcore.GetGrpcServerPublicKey()
}

func AddGrpcClientPublicKey(clientPublicKey []byte) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mobile.AddGrpcClientPublicKey panic: %v\n%s", r, string(debug.Stack()))
		}
	}()
	return hcore.AddGrpcClientPublicKey(clientPublicKey)
}

func Close(mode int) {
	defer func() {
		if r := recover(); r != nil {
			_ = fmt.Errorf("mobile.Close panic: %v\n%s", r, string(debug.Stack()))
		}
	}()
	hcore.Close(hcore.SetupMode(mode))
}

func Pause() {
	defer func() {
		if r := recover(); r != nil {
			_ = fmt.Errorf("mobile.Pause panic: %v\n%s", r, string(debug.Stack()))
		}
	}()
	hcore.Pause()
}

func Wake() {
	defer func() {
		if r := recover(); r != nil {
			_ = fmt.Errorf("mobile.Wake panic: %v\n%s", r, string(debug.Stack()))
		}
	}()
	hcore.Wake()
}
