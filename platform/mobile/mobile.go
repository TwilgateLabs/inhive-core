package mobile

import (
	"fmt"
	"runtime/debug"

	hcore "github.com/twilgate/inhive-core/v2/hcore"
	ray2sing "github.com/twilgate/xray2sing/ray2sing"

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

// Parse converts subscription content (base64 list / newline-separated share-link
// URIs / Xray-or-sing-box JSON) into a sing-box config JSON via the canonical
// xray2sing parser — the SINGLE source of truth for URI→outbound conversion,
// with full protocol knowledge (xhttp obfs, reality, vision, etc).
//
// Returns marshaled sing-box Options JSON: {"outbounds":[...], "endpoints":[...]}.
// The Flutter app calls this IN-PROCESS (the standalone main-process core is
// already MobileSetup'd at launch — no running NE/VPN required) and merges the
// returned outbounds into its own config skeleton (inbounds/route/dns/policy).
// This replaces the Dart-side reimplementation (singbox_config_builder) so the
// two parsers can no longer drift. Added 2026-06-23.
func Parse(content string) (configJSON string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("mobile.Parse panic: %v\n%s", r, string(debug.Stack()))
		}
	}()
	out, e := ray2sing.Ray2Singbox(libbox.BaseContext(nil), content, false)
	if e != nil {
		return "", e
	}
	return string(out), nil
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

// logPanic publishes a recovered panic into the core log bus.
//
// Почему: раньше эти recover-блоки делали `_ = fmt.Errorf(...)` — строили
// строку со стектрейсом и выбрасывали её. Комментарий утверждал «logging is
// the caller's responsibility», но caller — это gomobile-биндинг из Kotlin,
// а функции ниже НИЧЕГО не возвращают. Логировать было физически некому.
// Со стороны наблюдателя паника в Wake()/Pause()/Close() выглядела как
// «ничего не произошло»: VPN остаётся в паузе, трафик не идёт, в логах ядра
// и во вкладке «Логи» — чисто. Ровно тот класс, что уводит расследование.
func logPanic(fn string, r any) {
	hcore.Log(hcore.LogLevel_FATAL, hcore.LogType_CORE,
		fmt.Sprintf("mobile.%s panic: %v\n%s", fn, r, string(debug.Stack())))
}

func GetServerPublicKey() []byte {
	defer func() {
		if r := recover(); r != nil {
			logPanic("GetServerPublicKey", r)
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
			logPanic("Close", r)
		}
	}()
	hcore.Close(hcore.SetupMode(mode))
}

func Pause() {
	defer func() {
		if r := recover(); r != nil {
			logPanic("Pause", r)
		}
	}()
	hcore.Pause()
}

func Wake() {
	defer func() {
		if r := recover(); r != nil {
			logPanic("Wake", r)
		}
	}()
	hcore.Wake()
}
