package ray2sing

//based on https://github.com/XTLS/Xray-core/issues/91
//todo merge with https://github.com/XTLS/libXray/
import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"

	"strings"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

const USER_AGENT string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

type ParserFunc func(string) (*option.Outbound, error)
type EndpointParserFunc func(string) (*T.Endpoint, error)

func getTLSOptions(decoded map[string]string) T.OutboundTLSOptionsContainer {
	if !(decoded["tls"] == "tls" || decoded["tls"] == "reality" || decoded["security"] == "tls" || decoded["security"] == "reality") {
		return T.OutboundTLSOptionsContainer{TLS: nil}
	}

	serverName := decoded["sni"]
	if serverName == "" {
		// vless/trojan URIs have no "add" key; their CDN/front host lives in
		// "host". Prefer host over add so TLS SNI matches the front domain
		// (CDN / nginx-stream SNI routing) instead of the raw IP. Fall back to
		// add (vmess) only when host is absent.
		serverName = getOneOfN(decoded, "", "host")
	}
	if serverName == "" {
		serverName = decoded["add"]
	}

	var ECHOpts *option.OutboundECHOptions
	valECH, hasECH := decoded["ech"]
	if hasECH {
		ECHOpts = &option.OutboundECHOptions{
			Enabled: true,
		}
		if len(valECH) > 5 {
			if !strings.Contains(valECH, "-----BEGIN ECH CONFIGS-----") {
				valECH = "-----BEGIN ECH CONFIGS-----\n" + valECH + "\n-----END ECH CONFIGS-----"
			}
			ECHOpts.Config = badoption.Listable[string]{valECH}
		}
		// InHive: opt-in forced HTTPS-RR ECH query. When echForceQuery=1 (or an
		// explicit query_server_name is given) and no inline ech= blob was
		// supplied, set QueryServerName so the runtime fetches the ECHConfigList
		// via a DNS HTTPS record (option+runtime already plumbed). The query
		// name defaults to the SNI/front host. Absent => QueryServerName stays
		// empty (byte-identical: inline-blob or no-ECH behavior unchanged).
		if len(ECHOpts.Config) == 0 {
			if qsn := getOneOfN(decoded, "", "query_server_name", "echqueryservername"); qsn != "" {
				ECHOpts.QueryServerName = qsn
			} else if toBool(getOneOfN(decoded, "", "echforcequery", "ech_force_query"), false) {
				ECHOpts.QueryServerName = serverName
			}
		}
	}

	fp := decoded["fp"]
	if fp == "" && (decoded["security"] == "reality" || decoded["tls"] == "reality") {
		fp = "chrome"
	}
	insecure, err := getOneOf(decoded, "insecure", "allowinsecure")
	if err != nil {
		insecure = "false"
	}
	tlsOptions := &option.OutboundTLSOptions{
		Enabled:    true,
		ServerName: serverName,
		Insecure:   insecure == "true" || insecure == "1",
		DisableSNI: toBool(getOneOfN(decoded, "", "nosni"), false),
		ECH:        ECHOpts,
		TLSTricks:  getTricksOptions(decoded),
	}
	if fp != "" && !tlsOptions.DisableSNI {
		tlsOptions.UTLS = &option.OutboundUTLSOptions{
			Enabled:     true,
			Fingerprint: fp,
		}
	}

	// InHive: opt-in TLS min/max version pinning from the URI (Xray minVersion/
	// maxVersion). Values pass through verbatim to the already-supported
	// OutboundTLSOptions fields (runtime applies them on the std-TLS path).
	// Absent keys => empty strings => the stdlib default range (byte-identical).
	// NOTE: curvePreferences/cipherSuites are intentionally NOT read here — the
	// uTLS path drops CurvePreferences and these keys are virtually absent from
	// share links; deferred to avoid a half-working knob.
	if mv := getOneOfN(decoded, "", "minversion", "min_version"); mv != "" {
		tlsOptions.MinVersion = mv
	}
	if mv := getOneOfN(decoded, "", "maxversion", "max_version"); mv != "" {
		tlsOptions.MaxVersion = mv
	}

	if alpn, ok := decoded["alpn"]; ok && alpn != "" {
		net := getOneOfN(decoded, "net")
		if net == "" {
			net = getOneOfN(decoded, "type")
		}
		if net == "httpupgrade" || net == "ws" || net == "grpc" || net == "h2" {
			tlsOptions.ALPN = []string{"h2", "http/1.1"}
		} else {
			tlsOptions.ALPN = strings.Split(alpn, ",")
			isXhttp := getOneOfN(decoded, "", "type") == "xhttp" || getOneOfN(decoded, "", "net") == "xhttp"
			if getALPNversion(tlsOptions.ALPN) == 3 && isXhttp {
				tlsOptions.UTLS = nil //TODO utls quic has bug (h3 only)
			}
		}

	}

	// Reality lives here so every protocol (vless/vmess/trojan/naive) gets it.
	// vless/naive carry it as security=reality; vmess JSON uses tls=reality.
	if decoded["security"] == "reality" || decoded["tls"] == "reality" {
		tlsOptions.Reality = &option.OutboundRealityOptions{
			Enabled:   true,
			PublicKey: decoded["pbk"],
			ShortID:   decoded["sid"],
		}
	}

	return T.OutboundTLSOptionsContainer{
		TLS: tlsOptions,
	}

}

func getTricksOptions(decoded map[string]string) *option.TLSTricksOptions {
	// PaddingMode/PaddingSNI/PaddingSize (hiddify-lineage TLS padding tricks) were
	// dead — nothing in the runtime ever read them — so they were removed
	// 2026-06-23. Only MixedCaseSNI is live (utls_client.go/std_client.go honor it).
	if decoded["mc"] != "1" {
		return nil
	}
	return &option.TLSTricksOptions{MixedCaseSNI: true}
}
func getMuxOptions(decoded map[string]string) *option.OutboundMultiplexOptions {
	mux := option.OutboundMultiplexOptions{}
	mux.Protocol = decoded["muxtype"]
	if mux.Protocol == "" {
		return nil
	}
	mux.Enabled = true
	mux.MaxConnections = toInt(decoded["muxmaxc"])
	// mux.MinStreams = toInt(decoded["muxsmin"])
	mux.MaxStreams = toInt(decoded["muxsmax"])
	mux.MinStreams = toInt(decoded["mux"])
	mux.Padding = decoded["muxpad"] == "true"

	if decoded["muxup"] != "" && decoded["muxdown"] != "" {
		mux.Brutal = &option.BrutalOptions{
			Enabled:  true,
			UpMbps:   toInt(decoded["muxup"]),
			DownMbps: toInt(decoded["muxdown"]),
		}
	}
	return &mux
}
func getTransportOptions(decoded map[string]string) (*option.V2RayTransportOptions, error) {
	var transportOptions option.V2RayTransportOptions
	host, net, path := decoded["host"], decoded["net"], decoded["path"]
	if net == "" {
		net = decoded["type"]
	}
	if path == "" {
		// gRPC service name arrives under several key spellings. getOneOfN
		// normalizes the lookup (normalizeStr maps '-'/'_' -> space), so
		// "service-name"/"grpc-service-name" match the stored "service name".
		path = getOneOfN(decoded, "", "servicename", "service-name", "grpc-service-name")
	}
	if net == "raw" || net == "" {
		net = "tcp"
	}
	// fmoption.Printf("\n\nheaderType:%s, net:%s, type:%s\n\n", decoded["headerType"], net, decoded["type"])
	if (decoded["type"] == "http" || decoded["headertype"] == "http") && net == "tcp" {
		net = "http"
	}
	// net=h2 is the legacy alias for the HTTP/2 transport. sing-box has no "h2"
	// transport type; the generic "http" transport negotiates HTTP/2 over TLS
	// (getTLSOptions sets the h2 ALPN). Without this the whole outbound is
	// dropped ("unknown transport type: h2").
	if net == "h2" {
		net = "http"
	}
	// splithttp is the old name for xhttp (still emitted by marzban / old x-ui).
	// Route it through the existing xhttp case (which defaults ALPN to h2).
	if net == "splithttp" {
		net = "xhttp"
	}

	switch net {
	case "tcp":
		return nil, nil
	case "http":
		transportOptions.Type = C.V2RayTransportTypeHTTP
		if decoded["security"] != "tls" {
			transportOptions.HTTPOptions.Method = "GET"
		}
		// InHive: opt-in custom HTTP method from the URI (overrides the GET/PUT
		// default). Covers both net=h2 and the tcp+header.type=http obfs case
		// (Xray RAW request.method). Absent => the existing default is kept.
		if m := getOneOfN(decoded, "", "method", "http_method"); m != "" {
			transportOptions.HTTPOptions.Method = m
		}
		if host != "" {
			transportOptions.HTTPOptions.Host = badoption.Listable[string]{host}
		}
		httpPath := path
		if httpPath == "" {
			httpPath = "/"
		}
		transportOptions.HTTPOptions.Path = httpPath
		// InHive: opt-in custom request headers (JSON object), mirroring the
		// xhttp `headers` query key. Covers HTTP/2 per-node camouflage headers
		// and the tcp+header.type=http obfs (Accept/Connection/Pragma/...).
		// vmess nested header.request.headers is forwarded into decoded by
		// vmess.go (separate wave) as the same JSON-object string. Absent =>
		// Headers stays nil (byte-identical).
		if hdrs := getOneOfN(decoded, "", "headers"); hdrs != "" {
			var hdrMap map[string]string
			if jerr := json.Unmarshal([]byte(hdrs), &hdrMap); jerr == nil && len(hdrMap) > 0 {
				h := badoption.HTTPHeader{}
				for k, v := range hdrMap {
					h[k] = badoption.Listable[string]{v}
				}
				transportOptions.HTTPOptions.Headers = h
			}
		}
	case "httpupgrade":
		if decoded["alpn"] == "" {
			decoded["alpn"] = "http/1.1"
		}
		transportOptions.Type = C.V2RayTransportTypeHTTPUpgrade
		if host != "" {
			transportOptions.HTTPUpgradeOptions.Headers = badoption.HTTPHeader{"Host": {host}}
		}
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			pathURL, err := url.Parse(path)
			if err != nil {
				return &option.V2RayTransportOptions{}, err
			}
			// InHive: HTTPUpgrade early data (?ed=N). When the path carries an
			// ed= query, extract it into MaxEarlyData and STRIP it from the path
			// so the request line no longer mismatches server routing. Unlike
			// WebSocket (which uses the Sec-WebSocket-Protocol header by
			// default), httpupgrade early data is path-based, so
			// EarlyDataHeaderName is left empty. When ed is absent the path is
			// emitted unchanged and MaxEarlyData stays 0 — byte-identical.
			pathQuery := pathURL.Query()
			if maxEarlyDataString := pathQuery.Get("ed"); maxEarlyDataString != "" {
				if maxEarlyData, perr := strconv.ParseUint(maxEarlyDataString, 10, 32); perr == nil {
					transportOptions.HTTPUpgradeOptions.MaxEarlyData = uint32(maxEarlyData)
					pathQuery.Del("ed")
					pathURL.RawQuery = pathQuery.Encode()
				}
			}
			transportOptions.HTTPUpgradeOptions.Path = pathURL.String()
		}
	case "ws":
		if decoded["alpn"] == "" {
			decoded["alpn"] = "http/1.1"
		}
		transportOptions.Type = C.V2RayTransportTypeWebsocket
		if host != "" {
			transportOptions.WebsocketOptions.Headers = badoption.HTTPHeader{"Host": {host}}
		}
		// InHive: opt-in periodic WebSocket ping keepalive (Xray heartbeatPeriod,
		// bare seconds). Absent key => zero => no ping ticker (byte-identical).
		if v := getOneOfN(decoded, "", "heartbeatperiod", "heartbeat_period", "heartbeat"); v != "" {
			if n := toInt(v); n > 0 {
				transportOptions.WebsocketOptions.HeartbeatPeriod = badoption.Duration(time.Duration(n) * time.Second)
			}
		}
		if path != "" {
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			pathURL, err := url.Parse(path)
			if err != nil {
				return &option.V2RayTransportOptions{}, err
			}
			pathQuery := pathURL.Query()
			transportOptions.WebsocketOptions.MaxEarlyData = 0
			transportOptions.WebsocketOptions.EarlyDataHeaderName = "Sec-WebSocket-Protocol"
			maxEarlyDataString := pathQuery.Get("ed")
			if maxEarlyDataString != "" {
				maxEarlyDate, err := strconv.ParseUint(maxEarlyDataString, 10, 32)
				if err == nil {
					transportOptions.WebsocketOptions.MaxEarlyData = uint32(maxEarlyDate)
					pathQuery.Del("ed")
					pathURL.RawQuery = pathQuery.Encode()
				}
			}
			transportOptions.WebsocketOptions.Path = pathURL.String()
		}
	case "grpc":
		// gRPC runs over HTTP/2; default ALPN to h2 only when the user did not
		// supply one (mirror the xhttp case) instead of clobbering a custom alpn.
		if decoded["alpn"] == "" {
			decoded["alpn"] = "h2"
		}
		transportOptions.Type = C.V2RayTransportTypeGRPC
		grpcOpts := option.V2RayGRPCOptions{
			ServiceName:         path,
			IdleTimeout:         badoption.Duration(15 * time.Second),
			PingTimeout:         badoption.Duration(15 * time.Second),
			PermitWithoutStream: false,
		}
		// InHive: opt-in gRPC keepalive/CDN-fronting knobs from the URI. Each
		// guard leaves the existing 15s/false defaults untouched when the key
		// is absent, so output stays byte-identical for plain grpc nodes.
		//
		// idle_timeout / health_check_timeout arrive as bare seconds in share
		// links; map health_check_timeout -> PingTimeout (its keepalive ack
		// timeout), idle_timeout -> IdleTimeout (the keepalive ping interval).
		if v := getOneOfN(decoded, "", "idle_timeout", "idletimeout"); v != "" {
			if n := toInt(v); n > 0 {
				grpcOpts.IdleTimeout = badoption.Duration(time.Duration(n) * time.Second)
			}
		}
		if v := getOneOfN(decoded, "", "health_check_timeout", "healthchecktimeout"); v != "" {
			if n := toInt(v); n > 0 {
				grpcOpts.PingTimeout = badoption.Duration(time.Duration(n) * time.Second)
			}
		}
		if v := getOneOfN(decoded, "", "permit_without_stream", "permitwithoutstream"); v != "" {
			grpcOpts.PermitWithoutStream = toBool(v, false)
		}
		// Authority overrides the HTTP/2 :authority pseudo-header for CDN
		// fronting where the routing host differs from the TLS SNI.
		grpcOpts.Authority = getOneOfN(decoded, "", "authority")
		// UserAgent overrides the gRPC client User-Agent.
		grpcOpts.UserAgent = getOneOfN(decoded, "", "user_agent", "useragent")
		// NOTE: gRPC multiMode (mode=multi / multiMode=true → TunMulti stream)
		// is DEFERRED. Faithful support needs the multi-frame MultiHunk conn
		// codec (a new protobuf message + stream desc + codec), not just a
		// stream-path branch — a path-only change mis-frames the wire. The
		// cheap, high-value knobs (authority/user_agent/timeouts) are handled
		// above; multiMode awaits the codec port. mode is intentionally NOT
		// read here so a mode=gun (default) or mode=multi URI is parsed as the
		// standard single-frame gun transport (current behavior).
		transportOptions.GRPCOptions = grpcOpts
	case "quic":
		// QUIC negotiates HTTP/3; default ALPN to h3 only when the user did not
		// supply one (mirror the xhttp case) instead of clobbering a custom alpn.
		if decoded["alpn"] == "" {
			decoded["alpn"] = "h3"
		}
		transportOptions.Type = C.V2RayTransportTypeQUIC

	case "xhttp":
		// XHTTP/SplitHTTP servers (Xray default) negotiate HTTP/2 via ALPN.
		// Many subscription URLs omit `alpn`, which left NextProtos empty →
		// decideHTTPVersion fell back to HTTP/1.1 and the connection died.
		// Default to h2 (mirrors the grpc/quic cases above); keep an
		// explicit user alpn (e.g. h3) if provided.
		if decoded["alpn"] == "" {
			decoded["alpn"] = "h2"
		}
		transportOptions.Type = C.V2RayTransportTypeXHTTP
		transportOptions.XHTTPOptions = option.V2RayXHTTPOptions{
			Mode: getOneOfN(decoded, "auto", "mode"),
			V2RayXHTTPBaseOptions: option.V2RayXHTTPBaseOptions{
				Host: host,
				Path: path,
			},
		}

		if extra, ok := decoded["extra"]; ok {
			x := XHTTPExtra{}
			err := json.Unmarshal([]byte(extra), &x)
			if err != nil {
				return nil, err
			}
			transportOptions.XHTTPOptions.V2RayXHTTPBaseOptions = x.V2RayXHTTPBaseOptions
			if transportOptions.XHTTPOptions.Host == "" {
				transportOptions.XHTTPOptions.Host = host
			}
			if transportOptions.XHTTPOptions.Path == "" {
				transportOptions.XHTTPOptions.Path = path
			}
			if dl := x.DownloadSettings; dl != nil {
				transportOptions.XHTTPOptions.Download = &option.V2RayXHTTPDownloadOptions{
					V2RayXHTTPBaseOptions: dl.V2RayXHTTPBaseOptions,
					ServerOptions: option.ServerOptions{
						Server:     dl.Address,
						ServerPort: uint16(dl.Port),
					},
				}
				if transportOptions.XHTTPOptions.Download.Path == "" {
					transportOptions.XHTTPOptions.Download.Path = path
				}
				if dl.Security == "tls" && dl.TLSSettings != nil {
					transportOptions.XHTTPOptions.Download.TLS = &option.OutboundTLSOptions{
						Enabled:    true,
						ALPN:       dl.TLSSettings.ALPN,
						Insecure:   dl.TLSSettings.Insecure,
						ServerName: dl.TLSSettings.ServerName,
					}

					if dl.TLSSettings.Fingerprint != "" && getALPNversion(dl.TLSSettings.ALPN) != 3 {
						transportOptions.XHTTPOptions.Download.TLS.UTLS = &option.OutboundUTLSOptions{
							Enabled:     true,
							Fingerprint: dl.TLSSettings.Fingerprint,
						}
					}
				}
				if dl.Security == "reality" && dl.REALITYSettings != nil {
					transportOptions.XHTTPOptions.Download.TLS = &option.OutboundTLSOptions{
						Enabled: true,
						Reality: &option.OutboundRealityOptions{
							Enabled:   true,
							PublicKey: dl.REALITYSettings.PublicKey,
							ShortID:   dl.REALITYSettings.ShortId,
						},
						ServerName: dl.REALITYSettings.ServerName,
					}
					if dl.REALITYSettings.Fingerprint != "" {
						transportOptions.XHTTPOptions.Download.TLS.UTLS = &option.OutboundUTLSOptions{
							Enabled:     true,
							Fingerprint: dl.REALITYSettings.Fingerprint,
						}
					}
				}

			}

		}

		// Standalone xhttp query key: headers (JSON object). These are otherwise
		// only read from the `extra` JSON blob, so a URL that supplies headers as
		// a plain query param (custom CDN Host/UA) lost them. Only fill when the
		// extra block did not already set them.
		if transportOptions.XHTTPOptions.Headers == nil {
			if hdrs := getOneOfN(decoded, "", "headers"); hdrs != "" {
				var hdrMap map[string]string
				if err := json.Unmarshal([]byte(hdrs), &hdrMap); err == nil {
					transportOptions.XHTTPOptions.Headers = hdrMap
				}
			}
		}

		// 	var extraConfig option.V2RayXHTTPBaseOptions
		// 	err := json.Unmarshal([]byte(extra), &extraConfig)
		// 	if err != nil {
		// 		return nil, err
		// 	}
		// 	if headers, ok := extraConfig["headers"]; ok {
		// 		if headersMap, ok := headers.(map[string]string); ok {
		// 			transportOptions.XHTTPOptions.Headers = make(badoption.HTTPHeader, len(headersMap))
		// 			for k, v := range headersMap {
		// 				transportOptions.XHTTPOptions.Headers[k] = badoption.Listable[string]{v}
		// 			}
		// 		}
		// 	}
		// 	if dlsettings, ok := extraConfig["downloadSettings"]; ok {
		// 		if dlsettingsMap, ok := dlsettings.(map[string]any); ok {
		// 			if addr, ok := dlsettingsMap["address"]; ok {
		// 				if addrs, ok := addr.(string); ok {
		// 					transportOptions.XHTTPOptions.DownloadServer = addrs
		// 				}
		// 			}
		// 			if port, ok := dlsettingsMap["port"]; ok {
		// 				if portInt, ok := port.(int); ok {
		// 					transportOptions.XHTTPOptions.DownloadServerPort = uint16(portInt)
		// 				} else if portuInt, ok := port.(uint16); ok {
		// 					transportOptions.XHTTPOptions.DownloadServerPort = portuInt
		// 				} else if ports, ok := port.(string); ok {
		// 					transportOptions.XHTTPOptions.DownloadServerPort = toUInt16(ports, 0)
		// 				}
		// 			}

		// 		}
		// 	}
		// 	if noGRPCHeader, ok := extraConfig["noGRPCHeader"]; ok {
		// 		if noGRPCHeaderb, ok := noGRPCHeader.(bool); ok {
		// 			transportOptions.XHTTPOptions.NoGRPCHeader = noGRPCHeaderb
		// 		}
		// 	}
		// 	if noSSEHeader, ok := extraConfig["noSSEHeader"]; ok {
		// 		if noSSEHeaderb, ok := noSSEHeader.(bool); ok {
		// 			transportOptions.XHTTPOptions.NoGRPCHeader = noSSEHeaderb
		// 		}
		// 	}

		// 	if scMaxBufferedPosts, ok := extraConfig["scMaxBufferedPosts"]; ok {
		// 		if scMaxBufferedPosti, ok := scMaxBufferedPosts.(int); ok {
		// 			transportOptions.XHTTPOptions.MaxEachPostBytes = uint64(scMaxBufferedPosti)
		// 		}
		// 	}

		// res["extra"] = extraConfig
		// }

	case "kcp", "mkcp":
		// InHive: mKCP is not implemented by sing-box (and never was) — the
		// full kcp transport (seed + header obfs + mtu/tti/congestion) would be
		// a large from-scratch port. Return an explicit, diagnosable error so a
		// kcp node degrades clearly instead of surfacing the generic "unknown
		// transport type" as if it were a parser bug. DEFERRED: full kcp port.
		return nil, E.New("mKCP transport not supported by InHive core")

	default:
		return nil, E.New("unknown transport type: " + net)
	}

	return &transportOptions, nil
}
func getALPNversion(s []string) int {
	if len(s) == 0 {
		return 1
	}
	if s[0] == "h3" {
		return 3
	}
	if s[0] == "h2" {
		return 2
	}
	return 1
}

// func getV2RayXHTTPBaseOptions(extraConfig map[string]any) option.V2RayXHTTPBaseOptions {
// 	opts := option.V2RayXHTTPBaseOptions{}
// 	if headers, ok := extraConfig["headers"]; ok {
// 		if headersMap, ok := headers.(map[string]string); ok {
// 			opts.Headers = headersMap
// 		}
// 	}

// 	if noGRPCHeader, ok := extraConfig["noGRPCHeader"]; ok {
// 		if noGRPCHeaderb, ok := noGRPCHeader.(bool); ok {
// 			opts.NoGRPCHeader = noGRPCHeaderb
// 		}
// 	}
// 	if noSSEHeader, ok := extraConfig["noSSEHeader"]; ok {
// 		if noSSEHeaderb, ok := noSSEHeader.(bool); ok {
// 			opts.NoGRPCHeader = noSSEHeaderb
// 		}
// 	}

//		if scMaxBufferedPosts, ok := extraConfig["scMaxBufferedPosts"]; ok {
//			if scMaxBufferedPosti, ok := scMaxBufferedPosts.(int); ok {
//				opts.ScMaxBufferedPosts = int64(scMaxBufferedPosti)
//			}
//		}
//	}
func getDialerOptions(decoded map[string]string) option.DialerOptions {
	// Intentionally empty. The legacy hiddify-style per-outbound tls_fragment
	// (Size/Sleep/Method/Range) was a dead no-op — nothing in the runtime ever
	// read DialerOptions.TLSFragment — so it was removed 2026-06-23. Native TLS
	// fragmentation is the upstream sing-box route-action path
	// (metadata.TLSFragment -> tf.NewConn, which is SNI-aware). If per-outbound
	// fragment dialing is ever wanted, wire tf.NewConn into the dialer here.
	return option.DialerOptions{}
}

func decodeBase64IfNeeded(b64string string) (string, error) {

	decodedBytes, err := decodeBase64FaultTolerant(b64string)

	if err != nil {
		return b64string, err
	}

	return string(decodedBytes), nil
}

func toInt(s string) int {
	i, _ := strconv.Atoi(s)
	return i
}

func toBool(s string, def bool) bool {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "1":
		return true
	case "yes":
		return true
	case "on":
		return true
	case "false":
		return false
	case "0":
		return false
	case "no":
		return false
	case "off":
		return false
	default:
		return def
	}
}
func toIntN(s string) *int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &i
}

func toFloatN(s string) *float64 {
	i, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return &i
}
func toUInt16(s string, defaultPort uint16) uint16 {
	// bitSize 16 (unsigned) rejects negatives and values >65535 -> defaultPort.
	// The old bitSize 17 let "-1" parse and wrap to garbage instead.
	val, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		// fmoption.Printf("err %v", err)
		// handle the error appropriately; here we return 0
		return defaultPort
	}
	return uint16(val)
}

func toInt16(s string, defaultPort int16) int16 {
	val, err := strconv.ParseInt(s, 10, 16)
	if err != nil {
		// fmoption.Printf("err %v", err)
		// handle the error appropriately; here we return 0
		return defaultPort
	}
	return int16(val)
}

func isIPOnly(s string) bool {
	return net.ParseIP(s) != nil
}

func getOneOf(dic map[string]string, headers ...string) (string, error) {
	for _, h := range headers {
		if str, ok := dic[h]; ok {
			return str, nil
		}
	}
	return "", fmt.Errorf("not found")
}

func getOneOfN(dic map[string]string, defaultval string, headers ...string) string {
	for _, h := range headers {
		if str, ok := dic[normalizeStr(h)]; ok {
			return str
		}
	}
	return defaultval
}
