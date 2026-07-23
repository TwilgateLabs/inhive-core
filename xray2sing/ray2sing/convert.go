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
	// dnstt: снималось 2026-04-19 (дегиддификация), ре-добавлено 2026-07-22 —
	// клиентский outbound зарегистрирован, поля 1:1 с Dart (см. dnstt.go).
	"dnstt://": DnsttSingbox,
}
var endpointParsers = map[string]EndpointParserFunc{
	"wg://":        AWGSingbox,
	"wireguard://": AWGSingbox,
	"warp://":      WarpSingbox,
	"awg://":       AWGSingbox,
	"[Interface]":  AWGSingboxTxt,
}

// pairParsers — схемы, чья ОДНА ссылка разворачивается в ПАРУ связанных
// detour'ом outbound'ов (main + underlying-транспорт). Сейчас только utproto:
// vless-main дайлит через utproto-helper. Обычные ParserFunc возвращают один
// outbound и для пары не годятся. Тег/detour-линковку доделывает
// GenerateConfigLite.
var pairParsers = map[string]PairParserFunc{
	"utproto://": UTProtoSingbox,
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
	// helper — underlying-транспорт для outbound'а из pairParsers (utproto:
	// main.outbound=vless дайлит ЧЕРЕЗ helper=utproto). nil для одиночных
	// парсеров. GenerateConfigLite линкует main.detour → helper.tag.
	helper *T.Outbound
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

	// Pair-схемы (utproto): одна ссылка → main + helper. Пробуем только если
	// ни один одиночный парсер не сработал.
	if outend.outbound == nil && outend.endpoint == nil {
		for k, v := range pairParsers {
			if strings.HasPrefix(config, k) {
				outend.outbound, outend.helper, err = v(config)
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

			if outend.outbound != nil && outend.helper != nil {
				// Пара из pairParsers (utproto). helper — underlying-транспорт
				// main'а: main дайлит ЧЕРЕЗ helper (main.detour = helper.tag), а
				// helper продолжает внешнюю ' -> ' цепочку (detourTag). Суффиксуем
				// оба тега counter'ом (уникальность в пределах ОДНОГО парса — в
				// подписке counter монотонный по всем нодам). main добавляем
				// ПЕРВЫМ: hcore.AddOutbound берёт real[0] как главный (в селектор).
				main := outend.outbound
				helper := outend.helper
				main.Tag += " § " + strconv.Itoa(counter)
				counter += 1
				helper.Tag += " § " + strconv.Itoa(counter)
				if dialerOpt, ok := main.Options.(T.DialerOptionsWrapper); ok {
					d := dialerOpt.TakeDialerOptions()
					d.Detour = helper.Tag
					dialerOpt.ReplaceDialerOptions(d)
				}
				if dialerOpt, ok := helper.Options.(T.DialerOptionsWrapper); ok {
					d := dialerOpt.TakeDialerOptions()
					d.Detour = detourTag
					dialerOpt.ReplaceDialerOptions(d)
				}
				detourTag = main.Tag
				outbounds = append(outbounds, *main, *helper)

			} else if outend.outbound != nil {
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

// ConvertToShareLinks renders ANY subscription body into a canonical, per-server
// representation the app can preview/edit — the reverse of Ray2Singbox, and the
// single source of truth for "what is the share-link of this node".
//
// Input: base64 wrapper / plain share-link list / container JSON (sing-box,
// Xray, Happ, SIP008) / a single outbound-JSON / Clash YAML.
//
// Output: a newline-joined list of records, ONE PER SERVER, in INPUT ORDER. Each
// record is EITHER
//   - a canonical share-link URI — when the node's type is covered by the
//     canonicalizer AND round-trips (see singbox_ingest.go); its display name
//     rides in the #fragment; OR
//   - the minified single-node sing-box JSON (one line) — a faithful degradation
//     for a type we cannot yet canonicalize, so a server is NEVER lost
//     (universal-client). wireguard/awg endpoints degrade to endpoint JSON.
//
// A share-link input is already canonical and is returned as-is. An
// unrecognized / empty body is a hard error (the platform shim maps it to the
// same convention parse uses). This is a PURE function — no running engine — so
// the app can call it with the VPN off, exactly like Parse.
func ConvertToShareLinks(content string) (out string, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = ""
			stackTrace := make([]byte, 1024)
			s := runtime.Stack(stackTrace, false)
			err = E.New("Error in ConvertToShareLinks", r, "Stack trace:", string(stackTrace[:s]))
		}
	}()

	// Outer base64 unwrap, mirroring Ray2SingboxOptions (a JSON/Clash body is not
	// valid base64, so this is a no-op for containers).
	decoded, _ := decodeBase64IfNeeded(content)

	// Container JSON (sing-box / Xray / Happ / SIP008 / single outbound): needs
	// per-entry classification (canonical URI OR JSON fallback), the primary case.
	if records, ok := convertJSONEntries(decoded); ok {
		if len(records) == 0 {
			return "", E.New("No servers found")
		}
		return strings.Join(records, "\n"), nil
	}
	// Clash / Clash.Meta YAML: ingestClashYAML already rebuilds each proxy into a
	// canonical share-link URI (every Clash proxy type maps to a share-link
	// protocol), so its output is already the per-entry canonical form.
	if uris, ok := ingestClashYAML(decoded); ok {
		return uris, nil
	}
	// Otherwise a text/base64 share-link list — entries are already canonical,
	// returned as-is (one per line, input order). Guard against pure garbage the
	// same way parse does (which surfaces "No outbounds found"): require at least
	// one line to start with a known share-link scheme, else it is not a
	// subscription at all → hard error.
	records := expandDecodedConfig(decoded)
	recognized := false
	for _, r := range records {
		if splitPattern.MatchString(r) {
			recognized = true
			break
		}
	}
	if !recognized {
		return "", E.New("No servers found")
	}
	return strings.Join(records, "\n"), nil
}
