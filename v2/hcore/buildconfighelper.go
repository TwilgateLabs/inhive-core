// buildconfighelper.go — builds sing-box JSON config from gRPC StartRequest.
package hcore

import (
	"context"
	"encoding/json"
	"os"
	"sync"

	"github.com/twilgate/inhive-core/v2/config"
	"github.com/twilgate/inhive-core/v2/db"
	hcommon "github.com/twilgate/inhive-core/v2/hcommon"
	hutils "github.com/twilgate/inhive-core/v2/hutils"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/common/daita"
	"github.com/sagernet/sing-box/option"
)

func BuildConfigJson(ctx context.Context, in *StartRequest) (string, error) {
	Log(LogLevel_DEBUG, LogType_CORE, "Stating Service ")

	parsedContent, err := BuildConfig(ctx, in)
	if err != nil {
		return "", err
	}
	res, err := parsedContent.MarshalJSONContext(ctx)
	return string(res), err
}

func BuildConfig(ctx context.Context, in *StartRequest) (*option.Options, error) {
	Log(LogLevel_DEBUG, LogType_CORE, "Building Config...")

	// Inject DAITA Framework into context so outbound dialers wrap connections.
	ctx = initDaita(ctx)

	readOpt := &config.ReadOptions{Content: in.ConfigContent, Path: in.ConfigPath}
	if !in.EnableRawConfig {
		// S3.2 Phase A (2026-05-19) — assert invariant. All hot-path writers
		// (Flutter bridge.dart, mobile.go, standalone.go) send EnableRawConfig=true.
		// The InhiveOptions translation layer (~3000 LOC) is deprecated and will
		// be deleted in Phase B. If this branch is ever hit, the caller is broken
		// and must be fixed *before* Phase B ships — log loudly so the regression
		// is visible in journalctl / device logs.
		Log(LogLevel_ERROR, LogType_CORE, "S3.2.A.ASSERT: StartRequest.EnableRawConfig=false — falling back to legacy InhiveOptions translation. Caller must be fixed before Phase B (see project_enable_raw_config.md).")
		return config.BuildConfig(ctx, static.InhiveOptions, readOpt)
	}
	return config.ReadSingOptions(ctx, readOpt)
}

func initDaita(ctx context.Context) context.Context {
	opts := static.InhiveOptions
	if !opts.DaitaEnabled {
		return ctx
	}
	machines := opts.DaitaMachines
	if machines == "" {
		machines = DefaultDaitaMachines // use bundled Mullvad machines
	}
	maxPad := opts.DaitaMaxPad
	if maxPad <= 0 {
		maxPad = 0.1
	}
	fw, err := daita.NewFramework(machines, maxPad, 0)
	if err != nil {
		Log(LogLevel_WARNING, LogType_CORE, "DAITA init failed: "+err.Error())
		return ctx
	}
	if fw == nil {
		return ctx
	}
	Log(LogLevel_INFO, LogType_CORE, "DAITA: framework initialized")
	return daita.WithFramework(ctx, fw)
}

func (s *CoreService) Parse(ctx context.Context, in *ParseRequest) (resp *ParseResponse, err error) {
	defer config.RecoverPanicToError("CoreService.Parse", func(e error) {
		Log(LogLevel_FATAL, LogType_CORE, e.Error())
		resp = &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: e.Error()}
		err = e
	})
	return Parse(libbox.FromContext(ctx, nil), in)
}

func Parse(ctx context.Context, in *ParseRequest) (resp *ParseResponse, err error) {
	// Recover the panic into a normal error and FAILED response — never call
	// StopAndAlert here. Parse runs from background subscription updates
	// (profile_repository.go:296); a malformed remote config must NOT take down
	// the user's active tunnel. The gRPC wrapper at CoreService.Parse already
	// has its own RecoverPanicToError; this defer covers in-process callers.
	defer config.RecoverPanicToError("parse", func(panicErr error) {
		Log(LogLevel_FATAL, LogType_CONFIG, panicErr.Error())
		resp = &ParseResponse{ResponseCode: hcommon.ResponseCode_FAILED, Message: panicErr.Error()}
		err = panicErr
	})

	path := in.TempPath
	if path == "" {
		path = in.ConfigPath
	}

	config, err := config.ParseConfigBytes(ctx, &config.ReadOptions{Content: in.Content, Path: path}, true, static.InhiveOptions, false)
	if err != nil {
		return &ParseResponse{
			ResponseCode: hcommon.ResponseCode_FAILED,
			Message:      err.Error(),
		}, err
	}
	if in.ConfigPath != "" {
		err = os.WriteFile(in.ConfigPath, config, 0o600)
		if err != nil {
			return &ParseResponse{
				ResponseCode: hcommon.ResponseCode_FAILED,
				Message:      err.Error(),
			}, err
		}
	}
	return &ParseResponse{
		ResponseCode: hcommon.ResponseCode_OK,
		Content:      string(config),
		Message:      "",
	}, err
}

func (s *CoreService) ChangeInhiveSettings(ctx context.Context, in *ChangeInhiveSettingsRequest) (resp *CoreInfoResponse, err error) {
	return ChangeInhiveSettings(in, true)
}

// Сериализует конкурентные ChangeInhiveSettings (RPC из app может прилететь
// параллельно со стартом туннеля — регрессия 4.7.30 на iOS).
var changeSettingsMu sync.Mutex

// ChangeInhiveSettings принимает как ПОЛНЫЙ settings JSON, так и PARTIAL
// ({"log-level":"warn"}, {"daita-enabled":true}) — partial МЕРЖИТСЯ поверх
// текущих опций. До 2026-07-14 семантика была replace-all: partial сбрасывал
// все остальные поля в дефолт и персистил огрызок в БД — следующий Setup
// NE-процесса (iOS: каждый connect и шторка-старт) поднимался с дефолтами.
// Плюс static.InhiveOptions подменялся без синхронизации прямо во время
// чтения его стартом туннеля. Теперь: копия → merge → атомарная подмена
// указателя (читатели видят либо старый, либо новый снапшот целиком), в БД
// уходит полное смерженное состояние.
func ChangeInhiveSettings(in *ChangeInhiveSettingsRequest, insert bool) (*CoreInfoResponse, error) {
	changeSettingsMu.Lock()
	defer changeSettingsMu.Unlock()

	opts := config.DefaultInhiveOptions()
	if static.InhiveOptions != nil {
		*opts = *static.InhiveOptions
	}

	if in.InhiveSettingsJson != "" {
		if err := json.Unmarshal([]byte(in.InhiveSettingsJson), opts); err != nil {
			return nil, err
		}
		if opts.Warp.WireguardConfigStr != "" {
			if err := json.Unmarshal([]byte(opts.Warp.WireguardConfigStr), &opts.Warp.WireguardConfig); err != nil {
				return nil, err
			}
		}
		if opts.Warp2.WireguardConfigStr != "" {
			if err := json.Unmarshal([]byte(opts.Warp2.WireguardConfigStr), &opts.Warp2.WireguardConfig); err != nil {
				return nil, err
			}
		}
	}

	static.InhiveOptions = opts
	switch opts.LogLevel {
	case "debug":
		static.logLevel = LogLevel_DEBUG
	case "info":
		static.logLevel = LogLevel_INFO
	case "warn":
		static.logLevel = LogLevel_WARNING
	case "error":
		static.logLevel = LogLevel_ERROR
	case "fatal":
		static.logLevel = LogLevel_FATAL
	case "trace":
		static.logLevel = LogLevel_TRACE
	default:
		static.logLevel = LogLevel_INFO
	}
	static.debug = static.debug || static.logLevel <= LogLevel_DEBUG

	if insert && in.InhiveSettingsJson != "" {
		full, err := json.Marshal(opts)
		if err != nil {
			return nil, err
		}
		settings := db.GetTable[hcommon.AppSettings]()
		settings.UpdateInsert(&hcommon.AppSettings{
			Id:    "InHiveSettingsJson",
			Value: string(full),
		})
	}

	return &CoreInfoResponse{}, nil
}

func (s *CoreService) GenerateConfig(ctx context.Context, in *GenerateConfigRequest) (resp *GenerateConfigResponse, err error) {
	return GenerateConfig(libbox.FromContext(ctx, nil), in)
}

func GenerateConfig(ctx context.Context, in *GenerateConfigRequest) (resp *GenerateConfigResponse, err error) {
	// Same rationale as Parse: never StopAndAlert from a config-build helper.
	// CoreService.GenerateConfig wraps with its own RecoverPanicToError.
	defer config.RecoverPanicToError("generateConfig", func(panicErr error) {
		Log(LogLevel_FATAL, LogType_CONFIG, panicErr.Error())
		err = panicErr
	})
	if static.InhiveOptions == nil {
		static.InhiveOptions = config.DefaultInhiveOptions()
	}
	config, err := config.ParseBuildConfigBytes(ctx, static.InhiveOptions, &config.ReadOptions{Path: in.Path})
	if err != nil {
		return nil, err
	}

	return &GenerateConfigResponse{
		ConfigContent: string(config),
	}, nil
}

func removeTunnelIfNeeded(options *option.Options) (tuninb *option.TunInboundOptions) {
	if hutils.TunAllowed() {
		return nil
	}

	// Create a new slice to hold the remaining inbounds
	newInbounds := make([]option.Inbound, 0, len(options.Inbounds))

	for _, inb := range options.Inbounds {
		if inb.Type == C.TypeTun {
			if d, ok := inb.Options.(option.TunInboundOptions); ok {
				tuninb = &d
			}

		} else {
			newInbounds = append(newInbounds, inb)
		}
	}

	options.Inbounds = newInbounds
	return tuninb
}
