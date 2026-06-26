package ray2sing

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"strconv"
	"strings"

	_ "github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var configTypes = map[string]ParserFunc{
	"vmess://":       VmessSingbox,
	"vless://":       VlessSingbox,
	"trojan://":      TrojanSingbox,
	"svmess://":      VmessSingbox,
	"svless://":      VlessSingbox,
	"strojan://":     TrojanSingbox,
	"ss://":          ShadowsocksSingbox,
	"tuic://":        TuicSingbox,
	"hysteria://":    HysteriaSingbox,
	"hysteria2://":   Hysteria2Singbox,
	"hy2://":         Hysteria2Singbox,
	"ssh://":         SSHSingbox,
	"naive://":       NaiveSingbox,
	"naive+https://": NaiveSingbox,
	"naive+quic://":  NaiveSingbox,

	"ssconf://": BeepassSingbox,
	"direct://": DirectSingbox,
	// anytls/shadowtls: community share-link schemes (NekoBox/sublink-worker
	// convention); dialers already registered in sing-box. Added 2026-06-23.
	"anytls://":    AnyTLSSingbox,
	"shadowtls://": ShadowTLSSingbox,
	"socks://":     SocksSingbox,
	"socks4://":    SocksSingbox,
	"socks4a://":   SocksSingbox,
	"socks5://":    SocksSingbox,
	"socks5h://":   SocksSingbox,
	"phttp://":     HttpSingbox,
	"phttps://":    HttpsSingbox,
	"http://":      HttpSingbox,
	"https://":     HttpsSingbox,
	// x-prefixed URL schemes: 2026-04-20 dehiddification — переиспользуем native
	// sing-box парсеры вместо xray stub (у sing-box 1.12+ есть TLS Fragment,
	// XTLS Vision, uTLS, Reality — всё что нужно для xray-совместимых URI).
	"xvmess://":  VmessSingbox,
	"xvless://":  VlessSingbox,
	"xtrojan://": TrojanSingbox,
	"xdirect://": DirectSingbox,
	"mieru://":   MieruSingbox,
	"mierus://":  MieruSingbox,
	"psiphon://": PsiphonSingbox,
	// "dnstt://" removed 2026-04-19 (dehiddification) — re-add with clean net2share/vaydns upstream wrapper
}
var endpointParsers = map[string]EndpointParserFunc{
	"wg://":        AWGSingbox,
	"wireguard://": AWGSingbox,
	"warp://":      WarpSingbox,
	"awg://":       AWGSingbox,
	"[Interface]":  AWGSingboxTxt,
}

// xrayConfigTypes — legacy map для случаев когда подписка явно требует xray format.
// После дегиддификации 2026-04-20 — все парсятся через native sing-box types
// (sing-box имеет все xray-compatible фичи: TLS Fragment, XTLS Vision, uTLS).
var xrayConfigTypes = map[string]ParserFunc{
	"vmess://":  VmessSingbox,
	"vless://":  VlessSingbox,
	"trojan://": TrojanSingbox,
	"direct://": DirectSingbox,
}

func decodeUrlBase64IfNeeded(config string) string {
	splt := strings.SplitN(config, "://", 2)
	if len(splt) < 2 {
		//return config
	}
	rest, _ := decodeBase64IfNeeded(splt[1])
	// fmt.Println(rest, err)
	return splt[0] + "://" + rest
}

type OutEnd struct {
	outbound *T.Outbound
	endpoint *T.Endpoint
}

func processSingleConfig(config string, useXrayWhenPossible bool) (outend *OutEnd, err error) {
	defer func() {
		if r := recover(); r != nil {
			outend = nil
			stackTrace := make([]byte, 1024)
			s := runtime.Stack(stackTrace, false)
			stackStr := fmt.Sprint(string(stackTrace[:s]))
			err = E.New("Error in Parsing:", r, "Stack trace:", stackStr)
		}
	}()
	// configDecoded := decodeUrlBase64IfNeeded(config)
	outend = &OutEnd{}
	if false && (useXrayWhenPossible || strings.Contains(config, "&core=xray")) {
		for k, v := range xrayConfigTypes {
			if strings.HasPrefix(config, k) {
				outend.outbound, err = v(config)
				break
			}
		}
	}
	if outend.outbound == nil {
		for k, v := range configTypes {
			if strings.HasPrefix(config, k) {
				outend.outbound, err = v(config)
				break
			}
		}
		for k, v := range endpointParsers {
			if strings.HasPrefix(config, k) {
				outend.endpoint, err = v(config)
				break
			}
		}
	}

	if err != nil {
		return nil, err
	}
	if outend.endpoint == nil && outend.outbound == nil {
		return nil, E.New("Not supported config type")
	}
	if outend.outbound != nil && outend.outbound.Tag == "" {
		outend.outbound.Tag = outend.outbound.Type
	}
	if outend.endpoint != nil && outend.endpoint.Tag == "" {
		outend.endpoint.Tag = outend.endpoint.Type
	}

	// json.MarshalIndent(configSingbox, "", "  ")
	return outend, nil
}

func GenerateConfigLite(input string, useXrayWhenPossible bool) (*option.Options, error) {

	// JSON-container subscriptions (Happ / v2rayN Xray JSON, sing-box full
	// config, SIP008 server lists) import as ZERO nodes through the text/base64
	// share-link path, because expandDecodedConfig splits on newlines and shreds
	// a JSON body. Sniff the first non-space byte: '{' or '[' means JSON, which
	// we transcode back into share-link URIs and feed through the SAME pipeline
	// (so the per-protocol URI parsers stay the single source of truth). This is
	// strictly ADDITIVE — anything that is not a JSON object/array falls through
	// to the existing text/base64 handling unchanged.
	//
	// NOTE: ingestJSON intentionally ingests ONLY proxy outbounds/servers and
	// DROPS any embedded "dns"/"routing"/"rules" (InHive owns DNS + routing
	// centrally for leak protection). See json_ingest.go for the rationale.
	if uris, ok := ingestJSON(input); ok {
		input = uris
	} else if uris, ok := ingestClashYAML(input); ok {
		// Clash / Clash.Meta YAML (proxies:) — the other dominant container
		// format. Same rebuild-to-URI contract as the JSON path.
		input = uris
	}

	configArray := expandDecodedConfig(input)

	var outbounds []T.Outbound
	var endpoints []T.Endpoint
	counter := 0

	for _, config := range configArray {
		if len(config) < 5 || config[0] == '#' || config[0] == '/' {
			continue
		}
		detourTag := ""

		chains := strings.Split(config, " -> ")
		for i := len(chains) - 1; i >= 0; i-- {
			chain1 := chains[i]

			// fmt.Printf("%s", chain)
			chain, _ := decodeBase64IfNeeded(chain1)
			outend, err := processSingleConfig(chain, useXrayWhenPossible)

			if err != nil {
				fmt.Fprintf(os.Stderr, "Error in %s \n %v\n", config, err)

				continue
			}

			if outend.outbound != nil {
				outend.outbound.Tag += " § " + strconv.Itoa(counter)
				if dialerOpt, ok := outend.outbound.Options.(T.DialerOptionsWrapper); ok {
					d := dialerOpt.TakeDialerOptions()
					d.Detour = detourTag
					dialerOpt.ReplaceDialerOptions(d)
				}

				detourTag = outend.outbound.Tag
				outbounds = append(outbounds, *outend.outbound)

			} else if outend.endpoint != nil {
				outend.endpoint.Tag += " § " + strconv.Itoa(counter)
				if dialerOpt, ok := outend.endpoint.Options.(T.DialerOptionsWrapper); ok {
					d := dialerOpt.TakeDialerOptions()
					d.Detour = detourTag
					dialerOpt.ReplaceDialerOptions(d)
				}

				detourTag = outend.endpoint.Tag
				endpoints = append(endpoints, *outend.endpoint)

			}

			counter += 1

		}

	}

	if len(outbounds) == 0 && len(endpoints) == 0 {
		return nil, E.New("No outbounds found")
	}

	fullConfig := T.Options{
		Outbounds: outbounds,
		Endpoints: endpoints,
	}

	return &fullConfig, nil
}

func Ray2Singbox(ctx context.Context, configs string, useXrayWhenPossible bool) (out []byte, err error) {
	convertedData, err := Ray2SingboxOptions(ctx, configs, useXrayWhenPossible)
	// err = libbox.CheckConfigOptions(convertedData)
	// if err != nil {
	// 	return nil, err
	// }
	return convertedData.MarshalJSONContext(ctx)
}
func Ray2SingboxOptions(ctx context.Context, configs string, useXrayWhenPossible bool) (out *option.Options, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			stackTrace := make([]byte, 1024)
			s := runtime.Stack(stackTrace, false)
			stackStr := fmt.Sprint(string(stackTrace[:s]))
			err = E.New("Error in Parsing", configs, r, "Stack trace:", stackStr)

		}
	}()

	configs, _ = decodeBase64IfNeeded(configs)

	convertedData, err := GenerateConfigLite(configs, useXrayWhenPossible)
	return convertedData, err
}
