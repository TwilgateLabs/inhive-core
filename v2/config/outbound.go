// outbound.go — TLS tricks patching (fragment, mixed SNI, padding).
package config

import (
	"fmt"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

type outboundMap map[string]interface{}

func patchOutboundMux(base option.Outbound, configOpt InhiveOptions, obj outboundMap) outboundMap {
	if configOpt.Mux.Enable {
		multiplex := option.OutboundMultiplexOptions{
			Enabled:    true,
			Padding:    configOpt.Mux.Padding,
			MaxStreams: configOpt.Mux.MaxStreams,
			Protocol:   configOpt.Mux.Protocol,
		}
		obj["multiplex"] = multiplex
		// } else {
		// 	delete(obj, "multiplex")
	}
	return obj
}

func patchOutboundTLSTricks(base option.Outbound, configOpt InhiveOptions) option.Outbound {
	if base.Type == C.TypeSelector || base.Type == C.TypeURLTest || base.Type == C.TypeBlock || base.Type == C.TypeDNS {
		return base
	}
	if isOutboundReality(base) {
		return base
	}

	var tls *option.OutboundTLSOptions
	if tlsopt, ok := base.Options.(option.OutboundTLSOptionsWrapper); ok {
		tls = tlsopt.TakeOutboundTLSOptions()
	}

	var transport *option.V2RayTransportOptions
	if opts, ok := base.Options.(option.VLESSOutboundOptions); ok {
		transport = opts.Transport
	} else if opts, ok := base.Options.(option.TrojanOutboundOptions); ok {
		transport = opts.Transport
	} else if opts, ok := base.Options.(option.VMessOutboundOptions); ok {
		transport = opts.Transport
	}

	if base.Type == C.TypeDirect {
		// Direct outbounds get no TLS-tricks; the former patchOutboundFragment
		// (dead TLSFragment write) was removed 2026-06-23.
		return base
	}

	if tls == nil || !tls.Enabled || transport == nil {
		return base
	}

	if transport.Type != C.V2RayTransportTypeWebsocket && transport.Type != C.V2RayTransportTypeGRPC && transport.Type != C.V2RayTransportTypeHTTPUpgrade {
		return base
	}

	if tls.TLSTricks == nil {
		tls.TLSTricks = &option.TLSTricksOptions{}
	}
	tls.TLSTricks.MixedCaseSNI = tls.TLSTricks.MixedCaseSNI || configOpt.TLSTricks.MixedSNICase

	// EnablePadding path removed 2026-06-23: it set TLSTricks.PaddingMode/PaddingSize
	// (dead — no runtime consumer) + a coupled uTLS "custom" fingerprint that is only
	// meaningful with that padding spec. The whole TLS-padding feature was a no-op since
	// the sing-box upgrade. MixedCaseSNI stays live (honored by common/tls/{std,utls}_client).

	return base
}

func isOutboundReality(base option.Outbound) bool {
	// this function checks reality status ONLY FOR VLESS.
	// Some other protocols can also use reality, but it's discouraged as stated in the reality document
	if base.Type != C.TypeVLESS {
		return false
	}
	var tls *option.OutboundTLSOptions
	if tlsopt, ok := base.Options.(option.OutboundTLSOptionsWrapper); ok {
		tls = tlsopt.TakeOutboundTLSOptions()
	}

	if tls == nil || !tls.Enabled {
		return false
	}
	if tls.Reality == nil {
		return false
	}

	return tls.Reality.Enabled
}

func patchEndpoint(base *option.Endpoint, configOpt InhiveOptions, staticIPs *map[string][]string) (*option.Endpoint, error) {
	formatErr := func(err error) error {
		return fmt.Errorf("error patching outbound[%s][%s]: %w", base.Tag, base.Type, err)
	}
	err := patchWarp(base, &configOpt, true, *staticIPs)
	if err != nil {
		return nil, formatErr(err)
	}
	return base, nil
}
func patchOutbound(base option.Outbound, configOpt InhiveOptions, staticIPs *map[string][]string) (*option.Outbound, error) {

	base = patchOutboundTLSTricks(base, configOpt)

	return &base, nil
}
