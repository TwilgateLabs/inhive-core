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
	// Group/system outbounds (selector/urltest/loadbalance/direct/block/dns)
	// carry no server endpoint — they are not nodes, skip them silently.
	if ob.Server == "" || ob.ServerPort == 0 {
		skip(typ, "no server/server_port (group or system outbound)")
		return "", false
	}
	switch strings.ToLower(typ) {
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
