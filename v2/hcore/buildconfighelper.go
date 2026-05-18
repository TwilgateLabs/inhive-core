// buildconfighelper.go — builds sing-box JSON config from gRPC StartRequest.
package hcore

import (
	"context"
	"encoding/json"
	"os"

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

func ChangeInhiveSettings(in *ChangeInhiveSettingsRequest, insert bool) (*CoreInfoResponse, error) {
	static.InhiveOptions = config.DefaultInhiveOptions()
	defer func() {
		switch static.InhiveOptions.LogLevel {
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
	}()

	if in.InhiveSettingsJson == "" {
		return &CoreInfoResponse{}, nil
	}
	if insert {
		settings := db.GetTable[hcommon.AppSettings]()
		settings.UpdateInsert(&hcommon.AppSettings{
			Id:    "InHiveSettingsJson",
			Value: in.InhiveSettingsJson,
		})
	}

	err := json.Unmarshal([]byte(in.InhiveSettingsJson), static.InhiveOptions)
	if err != nil {
		return nil, err
	}

	if static.InhiveOptions.Warp.WireguardConfigStr != "" {
		err := json.Unmarshal([]byte(static.InhiveOptions.Warp.WireguardConfigStr), &static.InhiveOptions.Warp.WireguardConfig)
		if err != nil {
			return nil, err
		}
	}
	if static.InhiveOptions.Warp2.WireguardConfigStr != "" {
		err := json.Unmarshal([]byte(static.InhiveOptions.Warp2.WireguardConfigStr), &static.InhiveOptions.Warp2.WireguardConfig)
		if err != nil {
			return nil, err
		}
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
