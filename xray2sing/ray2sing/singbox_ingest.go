// singbox_ingest.go — native sing-box JSON outbound -> share-link URI.
//
// Providers increasingly serve a *sing-box* config (UA-gated: a client that
// presents as sing-box gets the full set, incl. hysteria2) instead of Xray JSON
// or share-links. A sing-box outbound is keyed by "type" (not Xray's
// "protocol"), with FLAT fields (server / server_port / uuid / password) plus
// nested tls{} and transport{}. json_ingest's uriFromAnyEntry dispatches these
// here. Same contract as the Xray path: rebuild a canonical share-link URI and
// feed the single per-protocol parser pipeline, so the list, ping and connect
// paths stay one source of truth. Group/system outbounds (selector / urltest /
// loadbalance / direct / block / dns) have no server -> skipped, never fatal.
//
// Round-trip is guarded by compat_corpus_test (a sing-box-JSON node and its
// share-link sibling must produce the same outbound).

package ray2sing

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type singboxOutbound struct {
	Type              string            `json:"type"`
	Tag               string            `json:"tag"`
	Server            string            `json:"server"`
	ServerPort        int               `json:"server_port"`
	UUID              string            `json:"uuid"`
	Password          string            `json:"password"`
	Method            string            `json:"method"`
	Flow              string            `json:"flow"`
	Security          string            `json:"security"` // vmess cipher
	AlterID           int               `json:"alter_id"`
	PacketEncoding    string            `json:"packet_encoding"`
	CongestionControl string            `json:"congestion_control"`
	UDPRelayMode      string            `json:"udp_relay_mode"`
	Obfs              *singboxObfs      `json:"obfs"`
	TLS               *singboxTLS       `json:"tls"`
	Transport         *singboxTransport `json:"transport"`
}

type singboxObfs struct {
	Type     string `json:"type"`
	Password string `json:"password"`
}

// stringOrList unmarshals BOTH a scalar string ("h2") and an array
// (["h2","http/1.1"]). sing-box's own `badoption.Listable[string]` marshals a
// SINGLE-element list AS a bare string, so a sing-box outbound that we emitted
// (alpn=["h2"] → "h2") and then round-trip back through THIS parser (the app
// stores a parsed server's uri as its sing-box-outbound JSON and re-parses it on
// every ping/connect) would otherwise fail `[]string` unmarshal → the whole
// outbound is dropped → the server shows blank in ping and can't connect. This
// bit every alpn-bearing node (gRPC/xhttp/hysteria2) coming from a Happ/sing-box
// subscription; plain TCP+reality (no alpn) was unaffected. 2026-07-06.
type stringOrList []string

func (s *stringOrList) UnmarshalJSON(data []byte) error {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	switch t := v.(type) {
	case string:
		if t != "" {
			*s = []string{t}
		}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if str, ok := e.(string); ok && str != "" {
				out = append(out, str)
			}
		}
		*s = out
	}
	return nil
}

type singboxTLS struct {
	Enabled    bool         `json:"enabled"`
	ServerName string       `json:"server_name"`
	Insecure   bool         `json:"insecure"`
	ALPN       stringOrList `json:"alpn"`
	UTLS       *struct {
		Enabled     bool   `json:"enabled"`
		Fingerprint string `json:"fingerprint"`
	} `json:"utls"`
	Reality *struct {
		Enabled   bool   `json:"enabled"`
		PublicKey string `json:"public_key"`
		ShortID   string `json:"short_id"`
	} `json:"reality"`
	// ECH was NOT read here at all: a sing-box-JSON node with Encrypted Client
	// Hello re-parsed into an outbound WITHOUT tls.ech, i.e. the ClientHello went
	// out with the SNI in PLAINTEXT. No error, node still connects — the user just
	// silently loses the exact property they enabled ECH for. Because the app
	// re-parses the stored outbound on every ping/connect, this degraded the node
	// permanently, not only at import. (Privacy-class silent-fail, 2026-07-19.)
	ECH *struct {
		Enabled         bool         `json:"enabled"`
		Config          stringOrList `json:"config"`
		ConfigPath      string       `json:"config_path"`
		QueryServerName string       `json:"query_server_name"`
	} `json:"ech"`
}

// singboxTransport mirrors a sing-box `transport` block across ALL transport
// types. Headers is map[string]stringOrList (not map[string]string) because
// sing-box's badoption.HTTPHeader marshals a multi-value header as an ARRAY —
// a plain map[string]string made the WHOLE outbound fail to unmarshal, so the
// node was dropped from the list entirely.
//
// raw keeps the untouched object so the xhttp case can forward every field
// sing-box knows (xmux / downloadSettings / sc* / the obfs set) through the
// `extra` channel instead of re-declaring ~40 fields here and drifting from
// upstream on the next merge.
type singboxTransport struct {
	Type        string                  `json:"type"` // ws / grpc / http / httpupgrade / xhttp / quic
	Path        string                  `json:"path"`
	Headers     map[string]stringOrList `json:"headers"`      // Host etc.
	ServiceName string                  `json:"service_name"` // grpc
	Host        json.RawMessage         `json:"host"`         // http: string OR []string; httpupgrade/xhttp: string

	// httpupgrade / ws early data.
	MaxEarlyData        uint32 `json:"max_early_data"`
	EarlyDataHeaderName string `json:"early_data_header_name"`

	// http (HTTP/2) request shaping.
	Method string `json:"method"`

	// keepalive knobs shared by http + grpc (sing-box duration strings, "15s").
	IdleTimeout         json.RawMessage `json:"idle_timeout"`
	PingTimeout         json.RawMessage `json:"ping_timeout"`
	HeartbeatPeriod     json.RawMessage `json:"heartbeat_period"` // ws
	PermitWithoutStream bool            `json:"permit_without_stream"`
	Authority           string          `json:"authority"`
	UserAgent           string          `json:"user_agent"`

	// xhttp.
	Mode string `json:"mode"`

	raw json.RawMessage
}

func (t *singboxTransport) UnmarshalJSON(data []byte) error {
	type plain singboxTransport
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*t = singboxTransport(p)
	t.raw = append(json.RawMessage(nil), data...)
	return nil
}

// header returns a single header value (first element of a multi-value header).
func (t *singboxTransport) header(key string) string {
	if t.Headers == nil {
		return ""
	}
	for _, k := range []string{key, strings.ToLower(key)} {
		if v, ok := t.Headers[k]; ok && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// hostString reads the `host` field, which is a bare string for
// httpupgrade/xhttp and a string-or-list for http (HTTP/2 host rotation).
// Returns the comma-joined form the share-link vocabulary uses.
func (t *singboxTransport) hostString() string {
	if len(t.Host) == 0 {
		return ""
	}
	var hs []string
	if err := json.Unmarshal(t.Host, &hs); err == nil {
		return strings.Join(hs, ",")
	}
	var h string
	if json.Unmarshal(t.Host, &h) == nil {
		return h
	}
	return ""
}

// singboxDuration converts a sing-box duration field ("15s", or raw nanoseconds)
// into the whole seconds the share-link vocabulary uses. 0 => key omitted.
func singboxDuration(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		if d, err := time.ParseDuration(s); err == nil {
			return int(d / time.Second)
		}
		return 0
	}
	var n int64
	if json.Unmarshal(raw, &n) == nil {
		return int(time.Duration(n) / time.Second)
	}
	return 0
}

// uriFromSingboxOutbound rebuilds a share-link URI from a native sing-box
// outbound. ok=false (skipped, non-fatal) for group/system/unsupported types.
func uriFromSingboxOutbound(raw json.RawMessage, typ string) (string, bool) {
	var ob singboxOutbound
	if err := json.Unmarshal(raw, &ob); err != nil {
		skip(typ, "sing-box outbound did not unmarshal: "+err.Error())
		return "", false
	}
	lt := strings.ToLower(typ)
	// Server-less-by-design node types must be handled BEFORE the group/system
	// server guard below (which keys on an empty server / server_port). dnstt
	// keys on a DNS delegation zone (no server), psiphon has no endpoint at all,
	// and a sing-box mieru outbound keeps server_port=0 (the ports live in
	// portBindings). Each round-trips through its per-protocol share-link parser.
	switch lt {
	case "dnstt":
		return singboxDnstt(raw)
	case "psiphon":
		return singboxPsiphon(raw)
	case "mieru":
		return singboxMieru(raw)
	}
	// Group/system outbounds (selector/urltest/loadbalance/direct/block/dns)
	// carry no server endpoint — they are not nodes, skip them silently.
	if ob.Server == "" || ob.ServerPort == 0 {
		skip(typ, "no server/server_port (group or system outbound)")
		return "", false
	}
	switch lt {
	case "hysteria2", "hy2":
		return singboxHysteria2(&ob)
	case "vless":
		return singboxVLESS(&ob)
	case "vmess":
		return singboxVMess(&ob)
	case "trojan":
		return singboxTrojan(&ob)
	case "shadowsocks":
		return singboxShadowsocks(&ob)
	case "tuic":
		return singboxTUIC(&ob)
	case "naive":
		return singboxNaive(raw)
	default:
		skip(typ, "sing-box type not rebuilt to a share-link (skipped, not fatal)")
		return "", false
	}
}

// applySingboxTLS writes security/sni/alpn/fp/pbk/sid for the transport-bearing
// protocols (vless/trojan) from a sing-box tls block.
func applySingboxTLS(q url.Values, tls *singboxTLS) {
	if tls == nil || !tls.Enabled {
		q.Set("security", "none")
		return
	}
	if tls.Reality != nil && tls.Reality.Enabled {
		q.Set("security", "reality")
		if tls.Reality.PublicKey != "" {
			q.Set("pbk", tls.Reality.PublicKey)
		}
		if tls.Reality.ShortID != "" {
			q.Set("sid", tls.Reality.ShortID)
		}
	} else {
		q.Set("security", "tls")
	}
	if tls.ServerName != "" {
		q.Set("sni", tls.ServerName)
	}
	if len(tls.ALPN) > 0 {
		q.Set("alpn", strings.Join(tls.ALPN, ","))
	}
	if tls.Insecure {
		q.Set("insecure", "1")
		q.Set("allowInsecure", "1")
	}
	if tls.UTLS != nil && tls.UTLS.Fingerprint != "" {
		q.Set("fp", tls.UTLS.Fingerprint)
	}
	applySingboxECH(q, tls)
}

// applySingboxECH re-encodes a sing-box tls.ech block into the `ech` share-link
// key that getTLSOptions understands. Was missing entirely => SNI in plaintext
// after every re-parse (see the comment on singboxTLS.ECH).
//
// Presence of the key alone enables ECH; a non-empty value is the inline
// ECHConfigList. config_path cannot survive a URI round-trip (it names a local
// file), so it degrades to "enabled with no inline config" — which is exactly
// sing-box's own DNS HTTPS-RR fetch path (common/tls/ech.go), i.e. ECH stays ON.
func applySingboxECH(q url.Values, tls *singboxTLS) {
	if tls == nil || tls.ECH == nil || !tls.ECH.Enabled {
		return
	}
	q.Set("ech", strings.Join(tls.ECH.Config, "\n"))
	if tls.ECH.QueryServerName != "" {
		q.Set("query_server_name", tls.ECH.QueryServerName)
	}
}

// applySingboxTransport writes net/path/host/serviceName/mode/extra from a
// sing-box transport block (default tcp when absent).
//
// 2026-07-19 — this function used to handle ws / grpc / http ONLY, and even
// there read just path+Host. Everything else was lost on re-parse:
//
//   - xhttp: NOTHING was carried over. The block emitted only type=xhttp, so
//     host/path collapsed to empty and mode fell back to "auto" — plus xmux,
//     downloadSettings, sc*, noGRPCHeader and the whole obfs set vanished. The
//     app re-parses the STORED outbound on every ping and every connect, so an
//     xhttp node degraded on each cycle, not just at import: it still built,
//     err == nil, and the traffic went out with the wrong URL and unbounded
//     stream reuse.
//   - httpupgrade: `host` is a TOP-LEVEL field in sing-box (not a Header), so a
//     CDN-fronted httpupgrade node silently lost its Host and hit the origin's
//     default vhost.
//   - grpc/http/ws keepalive + fronting knobs (authority, user_agent, timeouts,
//     method, heartbeat_period, early data) round-tripped to their defaults.
func applySingboxTransport(q url.Values, tr *singboxTransport) {
	if tr == nil || tr.Type == "" {
		q.Set("type", "tcp")
		return
	}
	q.Set("type", tr.Type)
	setPath := func() {
		if tr.Path != "" {
			q.Set("path", tr.Path)
		}
	}
	setSeconds := func(key string, raw json.RawMessage) {
		if n := singboxDuration(raw); n > 0 {
			q.Set(key, strconv.Itoa(n))
		}
	}
	switch tr.Type {
	case "ws":
		setPath()
		if h := tr.header("Host"); h != "" {
			q.Set("host", h)
		}
		// getTransportOptions reads WS early data out of the path's ?ed= query,
		// which is where Xray share-links carry it — put it back.
		if tr.MaxEarlyData > 0 && tr.Path != "" {
			q.Set("path", appendEarlyDataQuery(tr.Path, tr.MaxEarlyData))
		}
		setSeconds("heartbeat_period", tr.HeartbeatPeriod)
	case "httpupgrade":
		setPath()
		// host is a top-level field here; Headers["Host"] is only the legacy spelling.
		if h := tr.hostString(); h != "" {
			q.Set("host", h)
		} else if h := tr.header("Host"); h != "" {
			q.Set("host", h)
		}
		if tr.MaxEarlyData > 0 && tr.Path != "" {
			q.Set("path", appendEarlyDataQuery(tr.Path, tr.MaxEarlyData))
		}
	case "grpc":
		if tr.ServiceName != "" {
			q.Set("serviceName", tr.ServiceName)
		}
		setSeconds("idle_timeout", tr.IdleTimeout)
		setSeconds("health_check_timeout", tr.PingTimeout)
		if tr.PermitWithoutStream {
			q.Set("permit_without_stream", "1")
		}
		if tr.Authority != "" {
			q.Set("authority", tr.Authority)
		}
		if tr.UserAgent != "" {
			q.Set("user_agent", tr.UserAgent)
		}
	case "http":
		setPath()
		if h := tr.hostString(); h != "" {
			q.Set("host", h)
		}
		if tr.Method != "" {
			q.Set("method", tr.Method)
		}
		if hdrs := singleValueHeaders(tr.Headers); len(hdrs) > 0 {
			if b, err := json.Marshal(hdrs); err == nil {
				q.Set("headers", string(b))
			}
		}
		setSeconds("idle_timeout", tr.IdleTimeout)
		setSeconds("health_check_timeout", tr.PingTimeout)
	case "xhttp":
		setPath()
		if h := tr.hostString(); h != "" {
			q.Set("host", h)
		}
		if tr.Mode != "" {
			q.Set("mode", tr.Mode)
		}
		// Forward the WHOLE transport object through `extra` — the channel
		// getTransportOptions already uses for everything that has no query-param
		// spelling (xmux, downloadSettings, sc*, noGRPCHeader, uplinkHTTPMethod,
		// the obfs set). host/path/mode are also set above and win over `extra`
		// on the parser side, matching Xray's SplitHTTPConfig.Build.
		//
		// The sing-box spellings inside downloadSettings (server / server_port /
		// tls{}) are folded onto the Xray ones by DownloadSettings.UnmarshalJSON
		// (xhttp_extra.go), so both dialects land in the same struct.
		if len(tr.raw) > 0 {
			q.Set("extra", string(tr.raw))
		}
	}
}

// appendEarlyDataQuery re-attaches ?ed=N to a transport path so the share-link
// parser can lift it back into MaxEarlyData.
func appendEarlyDataQuery(path string, maxEarlyData uint32) string {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	return path + sep + "ed=" + strconv.FormatUint(uint64(maxEarlyData), 10)
}

// singleValueHeaders flattens a sing-box HTTPHeader to the single-value map the
// `headers` query key carries. Host is excluded — it travels as host=.
func singleValueHeaders(h map[string]stringOrList) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		if strings.EqualFold(k, "Host") || len(v) == 0 {
			continue
		}
		out[k] = v[0]
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func singboxHysteria2(ob *singboxOutbound) (string, bool) {
	q := url.Values{}
	if ob.TLS != nil {
		if ob.TLS.ServerName != "" {
			q.Set("sni", ob.TLS.ServerName)
		}
		if len(ob.TLS.ALPN) > 0 {
			q.Set("alpn", strings.Join(ob.TLS.ALPN, ","))
		}
		if ob.TLS.Insecure {
			q.Set("insecure", "1")
		}
	}
	if ob.Obfs != nil && ob.Obfs.Type != "" {
		q.Set("obfs", ob.Obfs.Type)
		if ob.Obfs.Password != "" {
			q.Set("obfs-password", ob.Obfs.Password)
		}
	}
	u := url.URL{
		Scheme:   "hysteria2",
		User:     url.User(ob.Password),
		Host:     hostPort(ob.Server, ob.ServerPort),
		RawQuery: q.Encode(),
		Fragment: ob.Tag,
	}
	return u.String(), true
}

func singboxVLESS(ob *singboxOutbound) (string, bool) {
	if ob.UUID == "" {
		skip("vless", "no uuid")
		return "", false
	}
	q := url.Values{}
	q.Set("encryption", "none")
	if ob.Flow != "" {
		q.Set("flow", ob.Flow)
	}
	if ob.PacketEncoding != "" {
		q.Set("packetEncoding", ob.PacketEncoding)
	}
	applySingboxTransport(q, ob.Transport)
	applySingboxTLS(q, ob.TLS)
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(ob.UUID),
		Host:     hostPort(ob.Server, ob.ServerPort),
		RawQuery: q.Encode(),
		Fragment: ob.Tag,
	}
	return u.String(), true
}

func singboxTrojan(ob *singboxOutbound) (string, bool) {
	if ob.Password == "" {
		skip("trojan", "no password")
		return "", false
	}
	q := url.Values{}
	applySingboxTransport(q, ob.Transport)
	applySingboxTLS(q, ob.TLS)
	// Trojan is TLS-by-spec — if the outbound carried no tls block, still mark tls.
	if sec := q.Get("security"); sec == "" || sec == "none" {
		q.Set("security", "tls")
	}
	u := url.URL{
		Scheme:   "trojan",
		User:     url.User(ob.Password),
		Host:     hostPort(ob.Server, ob.ServerPort),
		RawQuery: q.Encode(),
		Fragment: ob.Tag,
	}
	return u.String(), true
}

func singboxShadowsocks(ob *singboxOutbound) (string, bool) {
	if ob.Method == "" {
		skip("shadowsocks", "no method")
		return "", false
	}
	// SIP002: userinfo = base64url(method:password).
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(ob.Method + ":" + ob.Password))
	u := url.URL{
		Scheme:   "ss",
		User:     url.User(userinfo),
		Host:     hostPort(ob.Server, ob.ServerPort),
		Fragment: ob.Tag,
	}
	return u.String(), true
}

func singboxTUIC(ob *singboxOutbound) (string, bool) {
	if ob.UUID == "" {
		skip("tuic", "no uuid")
		return "", false
	}
	q := url.Values{}
	if ob.CongestionControl != "" {
		q.Set("congestion_control", ob.CongestionControl)
	}
	if ob.UDPRelayMode != "" {
		q.Set("udp_relay_mode", ob.UDPRelayMode)
	}
	if ob.TLS != nil {
		if ob.TLS.ServerName != "" {
			q.Set("sni", ob.TLS.ServerName)
		}
		if len(ob.TLS.ALPN) > 0 {
			q.Set("alpn", strings.Join(ob.TLS.ALPN, ","))
		}
		if ob.TLS.Insecure {
			q.Set("allow_insecure", "1")
		}
	}
	u := url.URL{
		Scheme:   "tuic",
		User:     url.UserPassword(ob.UUID, ob.Password),
		Host:     hostPort(ob.Server, ob.ServerPort),
		RawQuery: q.Encode(),
		Fragment: ob.Tag,
	}
	return u.String(), true
}

func singboxVMess(ob *singboxOutbound) (string, bool) {
	if ob.UUID == "" {
		skip("vmess", "no uuid")
		return "", false
	}
	// vmess share-link is base64(JSON) in the v2rayN "v:2" shape.
	m := map[string]string{
		"v":    "2",
		"ps":   ob.Tag,
		"add":  ob.Server,
		"port": strconv.Itoa(ob.ServerPort),
		"id":   ob.UUID,
		"aid":  strconv.Itoa(ob.AlterID),
		"scy":  orDefault(ob.Security, "auto"),
		"net":  "tcp",
		"type": "none",
	}
	if ob.PacketEncoding != "" {
		m["packetEncoding"] = ob.PacketEncoding
	}
	// vmess used to hand-roll its own (much smaller) subset of the transport/TLS
	// mapping: it copied net/path/host/sni/alpn and DROPPED insecure, the uTLS
	// fingerprint, reality (pbk/sid), ECH and every non-ws/grpc transport.
	//
	// Why each drop hurt, concretely:
	//   - insecure: getTLSOptions defaults Insecure=false, so a node pinned to a
	//     self-signed cert stopped verifying-as-configured and started FAILING the
	//     handshake (fails closed, not open — but the node is dead with a cert
	//     error that looks like a server problem).
	//   - fp: vmess.go substitutes fp=chrome when TLS is on and fp is empty, so a
	//     node fingerprinted as firefox/safari silently became chrome — the exact
	//     ClientHello signature the operator picked to evade DPI was replaced.
	//   - pbk/sid: reality was dropped to plain TLS => handshake against a REALITY
	//     server fails.
	// Now built through the SAME applySingboxTransport/applySingboxTLS used by
	// vless/trojan, so the three container branches can no longer drift apart.
	q := url.Values{}
	applySingboxTransport(q, ob.Transport)
	applySingboxTLS(q, ob.TLS)
	mergeQueryIntoVmessMap(m, q)
	if tr := ob.Transport; tr != nil && tr.Type == "grpc" && tr.ServiceName != "" {
		m["path"] = tr.ServiceName // legacy vmess carries the gRPC serviceName in path
	}
	b, err := json.Marshal(m)
	if err != nil {
		skip("vmess", "marshal: "+err.Error())
		return "", false
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b), true
}

// ---------------------------------------------------------------------------
// Extra sing-box outbound types (JSON -> canonical share-link URI).
//
// Each reverse function below is the inverse of one processSingleConfig parser
// (dnstt.go / psiphon.go / mieru.go / naive.go). The bar is a FAITHFUL
// round-trip: processSingleConfig(uriFromSingboxOutbound(json)) must be
// semantically identical to the input outbound (compat_corpus_test locks this).
// A field the forward parser cannot reconstruct means the type is NOT
// canonicalized for that node — it degrades to a JSON fallback in
// ConvertToShareLinks, never dropped (universal-client). The emitted query keys
// match BOTH the ray2sing forward parser and the Dart protocol registry
// (app/lib/features/proxy/data/protocol_registry.dart).
// ---------------------------------------------------------------------------

// singboxDnstt rebuilds dnstt://DOMAIN?pubkey=&resolver=#name. dnstt is
// server-less (it keys on a DNS delegation zone), so DnsttSingbox parses
// domain = host + escaped-path via url.Parse — mirror that by placing the whole
// zone in the authority+path. Query keys (pubkey/resolver) match DnsttSingbox
// and the Dart _parseDnstt registry entry.
func singboxDnstt(raw json.RawMessage) (string, bool) {
	var d struct {
		Tag      string `json:"tag"`
		Domain   string `json:"domain"`
		Pubkey   string `json:"pubkey"`
		Resolver string `json:"resolver"`
	}
	if err := json.Unmarshal(raw, &d); err != nil || d.Domain == "" || d.Pubkey == "" {
		skip("dnstt", "missing domain/pubkey")
		return "", false
	}
	q := url.Values{}
	q.Set("pubkey", d.Pubkey)
	if d.Resolver != "" {
		q.Set("resolver", d.Resolver)
	}
	name := d.Tag
	if name == "" {
		name = d.Domain
	}
	// Built by hand: the zone (host[+path]) must survive verbatim, and url.URL
	// would re-escape a hostname-only authority carrying a path suffix oddly.
	return "dnstt://" + d.Domain + "?" + q.Encode() + "#" + url.PathEscape(name), true
}

// singboxPsiphon rebuilds psiphon://?region=&remote_server_list_*=#name. Psiphon
// has no endpoint (PsiphonSingbox ignores host/port), so the authority is empty.
// Query keys match PsiphonSingbox's getOneOfN lookups and the Dart _parsePsiphon
// registry entry.
func singboxPsiphon(raw json.RawMessage) (string, bool) {
	var p struct {
		Tag                                string `json:"tag"`
		EgressRegion                       string `json:"egress_region"`
		RemoteServerListURL                string `json:"remote_server_list_url"`
		RemoteServerListDownloadFilename   string `json:"remote_server_list_download_filename"`
		RemoteServerListSignaturePublicKey string `json:"remote_server_list_signature_public_key"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		skip("psiphon", "outbound did not unmarshal")
		return "", false
	}
	q := url.Values{}
	if p.EgressRegion != "" {
		q.Set("region", p.EgressRegion)
	}
	if p.RemoteServerListURL != "" {
		q.Set("remote_server_list_url", p.RemoteServerListURL)
	}
	if p.RemoteServerListDownloadFilename != "" {
		q.Set("remote_server_list_download_filename", p.RemoteServerListDownloadFilename)
	}
	if p.RemoteServerListSignaturePublicKey != "" {
		q.Set("remote_server_list_signature_public_key", p.RemoteServerListSignaturePublicKey)
	}
	name := p.Tag
	if name == "" {
		name = "Psiphon"
	}
	uri := "psiphon://"
	if enc := q.Encode(); enc != "" {
		uri += "?" + enc
	}
	return uri + "#" + url.PathEscape(name), true
}

// singboxMieru rebuilds mieru://user:pass@server?protocol=&port=&...#name. A
// sing-box mieru outbound keeps server_port=0 and carries the ports inside
// portBindings, so the authority has NO port and MieruSingbox reads the aligned
// protocol/port lists from the query. Multiplexing/handshake-mode/mtu keys match
// MieruSingbox and the Dart _parseMieru registry entry.
func singboxMieru(raw json.RawMessage) (string, bool) {
	var m struct {
		Tag           string `json:"tag"`
		Server        string `json:"server"`
		Username      string `json:"username"`
		Password      string `json:"password"`
		Multiplexing  string `json:"multiplexing"`
		HandshakeMode string `json:"handshake_mode"`
		MTU           int    `json:"mtu"`
		PortBindings  []struct {
			Protocol  string `json:"protocol"`
			PortRange string `json:"portRange"`
			Port      uint16 `json:"port"`
		} `json:"portBindings"`
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.Server == "" || len(m.PortBindings) == 0 {
		skip("mieru", "missing server/portBindings")
		return "", false
	}
	protocols := make([]string, 0, len(m.PortBindings))
	ports := make([]string, 0, len(m.PortBindings))
	for _, b := range m.PortBindings {
		if b.Protocol == "" || (b.PortRange == "" && b.Port == 0) {
			skip("mieru", "portBinding missing protocol/port")
			return "", false
		}
		protocols = append(protocols, b.Protocol)
		if b.PortRange != "" {
			ports = append(ports, b.PortRange)
		} else {
			ports = append(ports, strconv.Itoa(int(b.Port)))
		}
	}
	q := url.Values{}
	q.Set("protocol", strings.Join(protocols, ","))
	q.Set("port", strings.Join(ports, ","))
	if m.Multiplexing != "" {
		q.Set("multiplexing", m.Multiplexing)
	}
	if m.HandshakeMode != "" {
		q.Set("handshake-mode", m.HandshakeMode)
	}
	if m.MTU != 0 {
		q.Set("mtu", strconv.Itoa(m.MTU))
	}
	name := m.Tag
	if name == "" {
		name = m.Server
	}
	u := url.URL{
		Scheme:   "mieru",
		User:     url.UserPassword(m.Username, m.Password),
		Host:     m.Server, // no port: portBindings carry the ports
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return u.String(), true
}

// singboxNaive rebuilds naive+https:// (or naive+quic://) from a sing-box naive
// outbound. NaiveSingbox negotiates ALPN inside cronet and force-zeroes
// tls.alpn/insecure/disable_sni, and the reverse path models neither
// extra_headers nor receive-window/ech/reality — so a node carrying any of those
// cannot be rebuilt without silent loss and is left to the JSON fallback (never
// dropped). The clean case (server/user/pass + sni + optional fp + quic knobs)
// round-trips. Keys match NaiveSingbox and the Dart _parseNaive registry entry.
func singboxNaive(raw json.RawMessage) (string, bool) {
	var n struct {
		Tag                      string                  `json:"tag"`
		Server                   string                  `json:"server"`
		ServerPort               int                     `json:"server_port"`
		Username                 string                  `json:"username"`
		Password                 string                  `json:"password"`
		InsecureConcurrency      int                     `json:"insecure_concurrency"`
		QUIC                     bool                    `json:"quic"`
		QUICCongestionControl    string                  `json:"quic_congestion_control"`
		ExtraHeaders             map[string]stringOrList `json:"extra_headers"`
		ReceiveWindow            json.RawMessage         `json:"stream_receive_window"`
		QUICSessionReceiveWindow json.RawMessage         `json:"quic_session_receive_window"`
		UDPOverTCP               *struct {
			Enabled bool `json:"enabled"`
		} `json:"udp_over_tcp"`
		TLS *singboxTLS `json:"tls"`
	}
	if err := json.Unmarshal(raw, &n); err != nil || n.Server == "" || n.ServerPort == 0 {
		skip("naive", "missing server/server_port")
		return "", false
	}
	// Faithful round-trip guard (see the function comment). Any of these means a
	// field the reverse cannot reconstruct → JSON fallback.
	if len(n.ExtraHeaders) > 0 || len(n.ReceiveWindow) > 0 || len(n.QUICSessionReceiveWindow) > 0 {
		return "", false
	}
	if n.TLS != nil {
		if len(n.TLS.ALPN) > 0 || n.TLS.Insecure ||
			(n.TLS.ECH != nil && n.TLS.ECH.Enabled) ||
			(n.TLS.Reality != nil && n.TLS.Reality.Enabled) {
			return "", false
		}
	}
	q := url.Values{}
	q.Set("security", "tls") // naive is TLS-by-spec; forward defaults it too
	if n.TLS != nil {
		if n.TLS.ServerName != "" {
			q.Set("sni", n.TLS.ServerName)
		}
		if n.TLS.UTLS != nil && n.TLS.UTLS.Fingerprint != "" {
			q.Set("fp", n.TLS.UTLS.Fingerprint)
		}
	}
	if n.InsecureConcurrency > 0 {
		q.Set("insecure_concurrency", strconv.Itoa(n.InsecureConcurrency))
	}
	if n.QUICCongestionControl != "" {
		q.Set("quic_congestion_control", n.QUICCongestionControl)
	}
	// UDPOverTCP: NaiveSingbox defaults enabled=true (uot != "false"/"0"); emit
	// uot=false only to reproduce an explicitly disabled UoT.
	if n.UDPOverTCP != nil && !n.UDPOverTCP.Enabled {
		q.Set("uot", "false")
	}
	scheme := "naive+https"
	if n.QUIC {
		scheme = "naive+quic"
	}
	name := n.Tag
	if name == "" {
		name = n.Server
	}
	u := url.URL{
		Scheme:   scheme,
		User:     url.UserPassword(n.Username, n.Password),
		Host:     hostPort(n.Server, n.ServerPort),
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return u.String(), true
}

// ---------------------------------------------------------------------------
// sing-box endpoint (wireguard / awg) -> canonical share-link URI.
//
// Endpoints live in the config's "endpoints" array (not "outbounds"), so the
// container walk collects them separately. AWGSingbox is the forward parser for
// wg:// / wireguard:// / awg://; a single share-link URI can only carry ONE
// peer, so a multi-peer endpoint (or one with WireGuard "noise" / listen_port /
// integrated-tun that the URI form cannot express) is NOT canonicalized and
// falls back to endpoint JSON. Query keys match AWGSingbox and the Dart
// _parseAmnezia / _buildWireguard registry entries (privatekey/peerpublickey/
// presharedkey/address/allowedips/keepalive/reserved/mtu, plus the AWG obfs set).
// ---------------------------------------------------------------------------

type singboxWGPeer struct {
	Address                     string       `json:"address"`
	Port                        uint16       `json:"port"`
	PublicKey                   string       `json:"public_key"`
	PreSharedKey                string       `json:"pre_shared_key"` // wireguard peer spelling
	PresharedKey                string       `json:"preshared_key"`  // awg peer spelling
	AllowedIPs                  stringOrList `json:"allowed_ips"`
	PersistentKeepaliveInterval uint16       `json:"persistent_keepalive_interval"`
	Reserved                    []int        `json:"reserved"`
}

type singboxEndpoint struct {
	Type             string          `json:"type"`
	Tag              string          `json:"tag"`
	PrivateKey       string          `json:"private_key"`
	Address          stringOrList    `json:"address"`
	MTU              uint32          `json:"mtu"`
	ListenPort       uint16          `json:"listen_port"`
	Workers          int             `json:"workers"`
	UseIntegratedTun bool            `json:"useIntegratedTun"`
	Noise            json.RawMessage `json:"noise"`
	Peers            []singboxWGPeer `json:"peers"`

	// AmneziaWG obfuscation set (presence flips the scheme to awg://).
	Jc, Jmin, Jmax     int    `json:"-"`
	S1, S2, S3, S4     int    `json:"-"`
	H1, H2, H3, H4     string `json:"-"`
	I1, I2, I3, I4, I5 string `json:"-"`
	J1, J2, J3         string `json:"-"`
	Itime              int    `json:"-"`
}

// UnmarshalJSON reads the AWG scalar fields alongside the shared endpoint fields
// without repeating the whole tag set on the exported struct.
func (e *singboxEndpoint) UnmarshalJSON(data []byte) error {
	type plain singboxEndpoint
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*e = singboxEndpoint(p)
	// Decode the AWG scalars explicitly (the exported fields are json:"-").
	var m struct {
		Jc    int    `json:"jc"`
		Jmin  int    `json:"jmin"`
		Jmax  int    `json:"jmax"`
		S1    int    `json:"s1"`
		S2    int    `json:"s2"`
		S3    int    `json:"s3"`
		S4    int    `json:"s4"`
		H1    string `json:"h1"`
		H2    string `json:"h2"`
		H3    string `json:"h3"`
		H4    string `json:"h4"`
		I1    string `json:"i1"`
		I2    string `json:"i2"`
		I3    string `json:"i3"`
		I4    string `json:"i4"`
		I5    string `json:"i5"`
		J1    string `json:"j1"`
		J2    string `json:"j2"`
		J3    string `json:"j3"`
		Itime int    `json:"itime"`
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	e.Jc, e.Jmin, e.Jmax = m.Jc, m.Jmin, m.Jmax
	e.S1, e.S2, e.S3, e.S4 = m.S1, m.S2, m.S3, m.S4
	e.H1, e.H2, e.H3, e.H4 = m.H1, m.H2, m.H3, m.H4
	e.I1, e.I2, e.I3, e.I4, e.I5 = m.I1, m.I2, m.I3, m.I4, m.I5
	e.J1, e.J2, e.J3 = m.J1, m.J2, m.J3
	e.Itime = m.Itime
	return nil
}

// hasWGNoise reports whether a WireGuard endpoint carries a non-empty "noise"
// (WARP-style fake-packet obfuscation). An empty/zero noise block round-trips to
// AWGSingbox's default (no noise); a non-empty one has no share-link spelling.
func hasWGNoise(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var probe struct {
		FakePacket struct {
			Enabled bool   `json:"enabled"`
			Count   string `json:"count"`
			Size    string `json:"size"`
			Delay   string `json:"delay"`
			Mode    string `json:"mode"`
		} `json:"fake_packet"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return false
	}
	fp := probe.FakePacket
	return fp.Enabled || fp.Mode != "" || fp.Count != "" || fp.Size != "" || fp.Delay != ""
}

func uriFromSingboxEndpoint(raw json.RawMessage) (string, bool) {
	var ep singboxEndpoint
	if err := json.Unmarshal(raw, &ep); err != nil {
		skip("endpoint", "sing-box endpoint did not unmarshal: "+err.Error())
		return "", false
	}
	typ := strings.ToLower(ep.Type)
	if typ != "wireguard" && typ != "awg" {
		// Other endpoint types (e.g. tailscale) have no share-link form.
		return "", false
	}
	// A single share-link carries exactly one peer and cannot express noise /
	// listen_port / integrated-tun — anything else degrades to endpoint JSON.
	if len(ep.Peers) != 1 || ep.ListenPort != 0 || ep.UseIntegratedTun || hasWGNoise(ep.Noise) {
		return "", false
	}
	p := ep.Peers[0]
	if ep.PrivateKey == "" || p.Address == "" || p.Port == 0 || p.PublicKey == "" {
		return "", false
	}
	isAwg := ep.Jc != 0 || ep.Jmin != 0 || ep.Jmax != 0 ||
		ep.S1 != 0 || ep.S2 != 0 || ep.S3 != 0 || ep.S4 != 0 || ep.Itime != 0 ||
		ep.H1 != "" || ep.H2 != "" || ep.H3 != "" || ep.H4 != "" ||
		ep.I1 != "" || ep.I2 != "" || ep.I3 != "" || ep.I4 != "" || ep.I5 != "" ||
		ep.J1 != "" || ep.J2 != "" || ep.J3 != ""

	q := url.Values{}
	// privatekey travels as a query param (not userinfo): wireguard:// in the
	// Dart registry has no userinfo, and AWGSingbox reads privatekey/pk from the
	// query before falling back to userinfo — so a param works for both schemes.
	q.Set("privatekey", ep.PrivateKey)
	q.Set("peerpublickey", p.PublicKey)
	if psk := orDefault(p.PreSharedKey, p.PresharedKey); psk != "" {
		q.Set("presharedkey", psk)
	}
	if addr := strings.Join(ep.Address, ","); addr != "" {
		q.Set("address", addr)
	}
	if len(p.AllowedIPs) > 0 {
		q.Set("allowedips", strings.Join(p.AllowedIPs, ","))
	}
	if p.PersistentKeepaliveInterval > 0 {
		q.Set("keepalive", strconv.Itoa(int(p.PersistentKeepaliveInterval)))
	}
	if len(p.Reserved) > 0 {
		parts := make([]string, len(p.Reserved))
		for i, r := range p.Reserved {
			parts[i] = strconv.Itoa(r)
		}
		q.Set("reserved", strings.Join(parts, ","))
	}
	if ep.MTU > 0 {
		q.Set("mtu", strconv.Itoa(int(ep.MTU)))
	}
	if ep.Workers > 0 {
		q.Set("workers", strconv.Itoa(ep.Workers))
	}
	scheme := "wireguard"
	if isAwg {
		scheme = "awg"
		setInt := func(k string, v int) {
			if v != 0 {
				q.Set(k, strconv.Itoa(v))
			}
		}
		setStr := func(k, v string) {
			if v != "" {
				q.Set(k, v)
			}
		}
		setInt("jc", ep.Jc)
		setInt("jmin", ep.Jmin)
		setInt("jmax", ep.Jmax)
		setInt("s1", ep.S1)
		setInt("s2", ep.S2)
		setInt("s3", ep.S3)
		setInt("s4", ep.S4)
		setStr("h1", ep.H1)
		setStr("h2", ep.H2)
		setStr("h3", ep.H3)
		setStr("h4", ep.H4)
		setStr("i1", ep.I1)
		setStr("i2", ep.I2)
		setStr("i3", ep.I3)
		setStr("i4", ep.I4)
		setStr("i5", ep.I5)
		setStr("j1", ep.J1)
		setStr("j2", ep.J2)
		setStr("j3", ep.J3)
		setInt("itime", ep.Itime)
	}
	name := ep.Tag
	if name == "" {
		name = p.Address
	}
	u := url.URL{
		Scheme:   scheme,
		Host:     hostPort(p.Address, int(p.Port)),
		RawQuery: q.Encode(),
		Fragment: name,
	}
	return u.String(), true
}
