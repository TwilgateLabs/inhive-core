package ray2sing

// json_ingest.go — JSON-container subscription ingestion.
//
// Background (P0 gap, audit 2026-06-23): Happ / v2rayN export *Xray JSON*
// (a full config object, or a bare array of outbound objects), and SIP008 is
// a Shadowsocks server-list standard ({"servers":[...]}). The historical
// ray2sing pipeline only understood the text/base64 share-link format, so any
// JSON body imported as ZERO nodes ("No outbounds found").
//
// DESIGN — rebuild-to-URI then reuse the existing per-protocol parsers.
// Rather than re-deriving sing-box outbound options here (which would fork the
// per-protocol logic into a second, drifting source of truth), we convert each
// JSON entry back into a vless:// / vmess:// / trojan:// / ss:// share-link URI
// and feed those URIs through the EXISTING expandDecodedConfig ->
// processSingleConfig path. The strong, battle-tested URI parsers stay the
// single source of truth; this file is just a faithful JSON->URI transcoder.
//
// DELIBERATE SCOPE — OUTBOUNDS ONLY. An Xray/Clash/sing-box *full* config also
// carries "dns" and "routing"/"rules". We intentionally INGEST ONLY THE
// PROXY/OUTBOUND ENTRIES and DROP "dns" and "routing"/"rules" on the floor.
// InHive owns DNS + routing centrally (anti-DNS-leak, kill-switch, geo rules);
// honoring a subscription's embedded dns/routing would (a) silently override
// our leak protection — a real DNS-leak surprise — and (b) couple node import
// to a foreign policy engine. So a top-level "dns" key is simply ignored, not
// an error. This drop is BY DESIGN, documented here so it is not a silent
// surprise to a future reader.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// looksLikeJSON sniffs the first non-space byte of a (possibly base64-decoded)
// subscription body. Returns the byte ('{' or '[') and true when the body is a
// JSON object/array; ('0', false) otherwise. Whitespace (incl. a UTF-8 BOM) is
// skipped. This is intentionally cheap and additive — anything that is not an
// object/array falls through to the existing text/base64 share-link path.
func looksLikeJSON(s string) (byte, bool) {
	// Strip a UTF-8 BOM if present.
	s = strings.TrimPrefix(s, "\ufeff")
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			continue
		}
		if c == '{' || c == '[' {
			return c, true
		}
		return 0, false
	}
	return 0, false
}

// ingestJSON converts a JSON-container subscription body into a newline-joined
// list of share-link URIs that the existing pipeline understands. It returns
// (uris, true) when at least one entry could be transcoded; (_, false) when the
// body is not a JSON shape we recognize (so the caller falls back to the
// text/base64 path). Entries that cannot be faithfully rebuilt are skipped with
// a logged warning rather than failing the whole import.
func ingestJSON(body string) (string, bool) {
	sniff, ok := looksLikeJSON(body)
	if !ok {
		return "", false
	}

	var uris []string

	switch sniff {
	case '[':
		// Two array shapes:
		//   (a) Happ "wrapper" form: [{"outbounds":[...], "dns":..., ...}, ...]
		//   (b) bare array of entries: [{...outbound...}, ...] or SIP008 servers.
		var rawItems []json.RawMessage
		if err := json.Unmarshal([]byte(body), &rawItems); err != nil {
			return "", false
		}
		for _, item := range rawItems {
			// Try the wrapper form first (object carrying "outbounds"/"servers").
			if added := urisFromContainerObject(item); len(added) > 0 {
				uris = append(uris, added...)
				continue
			}
			// Otherwise treat the item itself as a single entry (Xray outbound
			// object or SIP008 server object).
			if u, ok := uriFromAnyEntry(item); ok {
				uris = append(uris, u)
			}
		}

	case '{':
		// A single JSON object. Either a full config ({"outbounds":[...]} or
		// SIP008 {"servers":[...]}), or — degenerate — a single bare outbound.
		raw := json.RawMessage(body)
		if added := urisFromContainerObject(raw); len(added) > 0 {
			uris = append(uris, added...)
		} else if u, ok := uriFromAnyEntry(raw); ok {
			// Single bare outbound/server object with no wrapper array.
			uris = append(uris, u)
		}
	}

	if len(uris) == 0 {
		return "", false
	}
	return strings.Join(uris, "\n"), true
}

// containerObject is the union of the wrapper shapes we accept. We read ONLY
// "outbounds" (Xray/sing-box) and "servers" (SIP008). "dns" / "routing" /
// "rules" are deliberately NOT fields here — see the file header: they are
// dropped on purpose.
//
// "remarks"/"remark" is the Happ marker: Happ exports a JSON ARRAY where each
// element is a FULL Xray config object carrying the human node name in a
// top-level "remarks" field (the inner outbound is always the generic tag
// "proxy"). Its presence flips this object into "Happ per-node" mode (see
// urisFromContainerObject): emit exactly ONE server named by remarks, instead
// of expanding every outbound — otherwise Happ "Авто" bundles (which pack the
// whole node list as outbounds for client-side smart routing) would explode
// into dozens of duplicate "proxy" entries. (Happ ingest fix 2026-07-06.)
type containerObject struct {
	Outbounds []json.RawMessage `json:"outbounds"`
	Servers   []json.RawMessage `json:"servers"`
	Remarks   string            `json:"remarks"`
	Remark    string            `json:"remark"`
}

// urisFromContainerObject pulls the proxy entries out of a wrapper object and
// transcodes each to a URI. Returns nil when the object carries neither
// "outbounds" nor "servers".
func urisFromContainerObject(raw json.RawMessage) []string {
	var c containerObject
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil
	}

	// Happ per-node mode: a wrapper carrying "remarks" is one node whose real
	// name lives in remarks and whose inner outbounds are always tagged generic
	// "proxy"/"proxy-N". Emit exactly ONE server — the FIRST real proxy outbound
	// — renamed to remarks. This (a) restores the country name instead of
	// "proxy", and (b) collapses "Авто" bundles (which carry the whole server
	// list) to a single node, matching what the Happ client itself shows.
	if name := orDefault(c.Remarks, c.Remark); name != "" && len(c.Outbounds) > 0 {
		for _, ob := range c.Outbounds {
			if u, ok := uriFromAnyEntry(ob); ok {
				return []string{renameURIFragment(u, name)}
			}
			// non-proxy locals (freedom/blackhole/dns/…) are skipped by
			// uriFromAnyEntry → keep scanning for the first real proxy.
		}
		return nil
	}

	var uris []string
	// Xray/sing-box full config: ingest outbounds, drop dns/routing (by design).
	for _, ob := range c.Outbounds {
		if u, ok := uriFromAnyEntry(ob); ok {
			uris = append(uris, u)
		}
	}
	// SIP008: a Shadowsocks server list.
	for _, sv := range c.Servers {
		if u, ok := uriFromSIP008(sv); ok {
			uris = append(uris, u)
		}
	}
	return uris
}

// renameURIFragment overwrites the #fragment (display name) of an already-built
// share-link URI. Used by the Happ per-node path to stamp the top-level
// "remarks" name over the generic inner outbound tag ("proxy"). If the URI
// cannot be parsed it is returned unchanged (defensive; should not happen for
// URIs we just built).
func renameURIFragment(uri, name string) string {
	u, err := url.Parse(uri)
	if err != nil {
		return uri
	}
	u.Fragment = name
	return u.String()
}

// uriFromAnyEntry decides whether a JSON object is an Xray-style outbound (has
// a "protocol" key) or a SIP008 server object (has "method"+"password" but no
// "protocol") and dispatches accordingly.
func uriFromAnyEntry(raw json.RawMessage) (string, bool) {
	var probe struct {
		Protocol string          `json:"protocol"`
		Type     string          `json:"type"`
		Method   string          `json:"method"`
		Password json.RawMessage `json:"password"`
		Server   string          `json:"server"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return "", false
	}
	if probe.Protocol != "" {
		return uriFromXrayOutbound(raw, probe.Protocol)
	}
	// Native sing-box outbound: keyed by "type" (vs Xray's "protocol"). A sing-box
	// shadowsocks outbound ALSO carries method+password, so this MUST precede the
	// SIP008 check below or it would be misrouted.
	if probe.Type != "" {
		return uriFromSingboxOutbound(raw, probe.Type)
	}
	// No "protocol"/"type" but looks like a SIP008 server entry.
	if probe.Method != "" && probe.Server != "" {
		return uriFromSIP008(raw)
	}
	skip("entry", "no recognizable protocol/method/type key")
	return "", false
}

// ---------------------------------------------------------------------------
// Xray outbound object -> share-link URI
// ---------------------------------------------------------------------------

// xrayOutbound mirrors the relevant subset of an Xray (and largely v2ray-core)
// outbound object. Fields not needed to rebuild a share-link are ignored.
type xrayOutbound struct {
	Protocol string          `json:"protocol"`
	Tag      string          `json:"tag"`
	Settings json.RawMessage `json:"settings"`
	Stream   *xrayStream     `json:"streamSettings"`
}

type xrayStream struct {
	Network         string               `json:"network"`
	Security        string               `json:"security"`
	TLSSettings     *xrayTLSSettings     `json:"tlsSettings"`
	RealitySettings *xrayRealitySettings `json:"realitySettings"`
	WSSettings      *xrayWSSettings      `json:"wsSettings"`
	HTTPUpgrade     *xrayWSSettings      `json:"httpupgradeSettings"`
	GRPCSettings    *xrayGRPCSettings    `json:"grpcSettings"`
	HTTPSettings    *xrayHTTPSettings    `json:"httpSettings"`
	XHTTPSettings   *xrayXHTTPSettings   `json:"xhttpSettings"`
	SplitHTTP       *xrayXHTTPSettings   `json:"splithttpSettings"`
	TCPSettings     *xrayTCPSettings     `json:"tcpSettings"`
	Hysteria        *xrayHysteriaStream  `json:"hysteriaSettings"`
}

// xrayHysteriaStream is the Happ/v2rayN hysteria2 transport block. The auth
// string (== hy2 password) lives here, NOT in settings.
type xrayHysteriaStream struct {
	Version int    `json:"version"`
	Auth    string `json:"auth"`
	Obfs    string `json:"obfs"`
}

// xrayTCPSettings models the TCP transport's HTTP/1.1 header obfuscation
// (tcpSettings.header.type=http). Xray stores request path and Host headers as
// ARRAYS. The field was previously a dead map[string]interface{} (never read), so
// the obfuscation was silently dropped on JSON ingest. (Audit 2026-06-26.)
type xrayTCPSettings struct {
	Header struct {
		Type    string `json:"type"`
		Request struct {
			Path    []string            `json:"path"`
			Headers map[string][]string `json:"headers"`
		} `json:"request"`
	} `json:"header"`
}

type xrayTLSSettings struct {
	ServerName    string   `json:"serverName"`
	SNI           string   `json:"sni"`
	ALPN          []string `json:"alpn"`
	Fingerprint   string   `json:"fingerprint"`
	AllowInsecure bool     `json:"allowInsecure"`
}

type xrayRealitySettings struct {
	ServerName  string `json:"serverName"`
	SNI         string `json:"sni"`
	PublicKey   string `json:"publicKey"`
	ShortID     string `json:"shortId"`
	ShortIDAlt  string `json:"shortID"`
	SpiderX     string `json:"spiderX"`
	Fingerprint string `json:"fingerprint"`
}

type xrayWSSettings struct {
	Path    string            `json:"path"`
	Host    string            `json:"host"`
	Headers map[string]string `json:"headers"`
}

type xrayGRPCSettings struct {
	ServiceName string `json:"serviceName"`
}

type xrayHTTPSettings struct {
	Path string   `json:"path"`
	Host []string `json:"host"`
}

type xrayXHTTPSettings struct {
	Path  string          `json:"path"`
	Host  string          `json:"host"`
	Mode  string          `json:"mode"`
	Extra json.RawMessage `json:"extra"`

	// raw — весь объект xhttpSettings как он пришёл. Заполняется в
	// UnmarshalJSON ниже и нужен, чтобы НЕ терять top-level поля, которых нет в
	// этой структуре (xmux, downloadSettings, sc*, headers, noGRPCHeader,
	// uplinkHTTPMethod и весь obfs-набор). См. applyStreamToQuery.
	raw json.RawMessage
}

// UnmarshalJSON сохраняет исходный объект целиком.
//
// InHive 2026-07-19: JSON-путь разбирал xhttpSettings ровно в 4 поля
// (path/host/mode/extra) и МОЛЧА выбрасывал всё остальное, что умеет Xray
// (infra/conf/transport_method.go SplitHTTPConfig — там 30 полей). Чужая
// подписка в JSON-формате с `xmux` или `downloadSettings` приезжала к нам
// урезанной: конфиг строился, err == nil, трафик шёл по неверным параметрам —
// ровно тот silent-fail, из-за которого JSON-ingest уже ловили в аудите
// 2026-06-26. Держать здесь копию всех 30 полей — гарантированный источник
// дрейфа при каждом апстрим-релизе, поэтому пробрасываем объект целиком.
func (x *xrayXHTTPSettings) UnmarshalJSON(data []byte) error {
	type plain xrayXHTTPSettings
	var p plain
	if err := json.Unmarshal(data, &p); err != nil {
		return err
	}
	*x = xrayXHTTPSettings(p)
	x.raw = append(json.RawMessage(nil), data...)
	return nil
}

// uriFromXrayOutbound builds the matching share-link URI for the supported
// protocols. Anything else is skipped (logged) so the import does not fail.
func uriFromXrayOutbound(raw json.RawMessage, protocol string) (string, bool) {
	var ob xrayOutbound
	if err := json.Unmarshal(raw, &ob); err != nil {
		skip(protocol, "outbound object did not unmarshal: "+err.Error())
		return "", false
	}
	switch strings.ToLower(protocol) {
	case "vless":
		return xrayVLESS(&ob)
	case "vmess":
		return xrayVMess(&ob)
	case "trojan":
		return xrayTrojan(&ob)
	case "shadowsocks":
		return xrayShadowsocks(&ob)
	case "hysteria2", "hysteria":
		// Happ exports hysteria2 under protocol "hysteria" with
		// streamSettings.hysteriaSettings.version==2 (v2rayN/Happ dialect).
		// settings.version==2 is the alternate marker. hysteria v1 is not a
		// share-link protocol here → rebuilt only when it is really v2.
		return xrayHysteria2(&ob)
	default:
		// freedom/blackhole/dns/socks/http/wireguard/etc. are either local
		// helpers (not a remote node) or protocols we cannot faithfully
		// round-trip through a share-link. Skip, never fail the import.
		skip(protocol, "protocol not rebuilt to a share-link (skipped, not fatal)")
		return "", false
	}
}

// vnextSettings is the {"vnext":[{address,port,users:[{id,flow,encryption,...}]}]}
// shape used by vless/vmess outbounds.
type vnextSettings struct {
	Vnext []struct {
		Address string `json:"address"`
		Port    int    `json:"port"`
		Users   []struct {
			ID         string      `json:"id"`
			Flow       string      `json:"flow"`
			Encryption string      `json:"encryption"`
			Security   string      `json:"security"`
			AlterID    json.Number `json:"alterId"`
		} `json:"users"`
	} `json:"vnext"`
}

func xrayVLESS(ob *xrayOutbound) (string, bool) {
	var s vnextSettings
	if err := json.Unmarshal(ob.Settings, &s); err != nil || len(s.Vnext) == 0 || len(s.Vnext[0].Users) == 0 {
		skip("vless", "missing vnext/users")
		return "", false
	}
	srv := s.Vnext[0]
	usr := srv.Users[0]

	q := url.Values{}
	q.Set("encryption", orDefault(usr.Encryption, "none"))
	if usr.Flow != "" {
		q.Set("flow", usr.Flow)
	}
	applyStreamToQuery(q, ob.Stream)

	u := url.URL{
		Scheme:   "vless",
		User:     url.User(usr.ID),
		Host:     hostPort(srv.Address, srv.Port),
		RawQuery: q.Encode(),
		Fragment: ob.Tag,
	}
	return u.String(), true
}

func xrayTrojan(ob *xrayOutbound) (string, bool) {
	// Trojan settings use {"servers":[{address,port,password,...}]}.
	var s struct {
		Servers []struct {
			Address  string `json:"address"`
			Port     int    `json:"port"`
			Password string `json:"password"`
			Flow     string `json:"flow"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(ob.Settings, &s); err != nil || len(s.Servers) == 0 {
		skip("trojan", "missing servers[]")
		return "", false
	}
	srv := s.Servers[0]

	q := url.Values{}
	if srv.Flow != "" {
		q.Set("flow", srv.Flow)
	}
	applyStreamToQuery(q, ob.Stream)
	// trojan needs an explicit security flag; default TLS on when the stream
	// did not set one (trojan is TLS-by-spec).
	if q.Get("security") == "" {
		q.Set("security", "tls")
	}

	u := url.URL{
		Scheme:   "trojan",
		User:     url.User(srv.Password),
		Host:     hostPort(srv.Address, srv.Port),
		RawQuery: q.Encode(),
		Fragment: ob.Tag,
	}
	return u.String(), true
}

func xrayShadowsocks(ob *xrayOutbound) (string, bool) {
	// SS Xray settings: {"servers":[{address,port,method,password}]}.
	var s struct {
		Servers []struct {
			Address  string `json:"address"`
			Port     int    `json:"port"`
			Method   string `json:"method"`
			Password string `json:"password"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(ob.Settings, &s); err != nil || len(s.Servers) == 0 {
		skip("shadowsocks", "missing servers[]")
		return "", false
	}
	srv := s.Servers[0]
	return buildSSURI(srv.Method, srv.Password, srv.Address, srv.Port, ob.Tag, ""), true
}

// xrayHysteria2 rebuilds a hysteria2:// URI from the Happ/v2rayN "hysteria"
// outbound. Shape (observed on live xpnet Happ export):
//
//	{"protocol":"hysteria",
//	 "settings":{"address":"h.example","port":8449,"version":2},
//	 "streamSettings":{"network":"hysteria",
//	   "hysteriaSettings":{"version":2,"auth":"<password>"},
//	   "security":"tls",
//	   "tlsSettings":{"serverName":"h.example","alpn":["h3"],"allowInsecure":false}}}
//
// The auth string is the hy2 password; sni/alpn/insecure come from tlsSettings.
// hysteria v1 is not rebuilt here (no share-link round-trip in this file) — we
// only accept it when version==2 markers are present.
func xrayHysteria2(ob *xrayOutbound) (string, bool) {
	var s struct {
		Address  string      `json:"address"`
		Port     int         `json:"port"`
		Version  json.Number `json:"version"`
		Auth     string      `json:"auth"`
		Password string      `json:"password"`
	}
	if err := json.Unmarshal(ob.Settings, &s); err != nil || s.Address == "" {
		skip("hysteria2", "missing settings.address")
		return "", false
	}

	// Confirm this is hysteria2, not hysteria1. Version markers can live in
	// settings.version or streamSettings.hysteriaSettings.version.
	v2 := s.Version.String() == "2"
	var hs *xrayHysteriaStream
	if ob.Stream != nil {
		hs = ob.Stream.Hysteria
	}
	if hs != nil && hs.Version == 2 {
		v2 = true
	}
	if !v2 {
		skip("hysteria", "not hysteria2 (v1 not rebuilt to a share-link)")
		return "", false
	}

	// password/auth precedence: streamSettings.hysteriaSettings.auth, then
	// settings.auth/password.
	password := ""
	if hs != nil {
		password = hs.Auth
	}
	password = orDefault(password, orDefault(s.Auth, s.Password))

	q := url.Values{}
	if ob.Stream != nil && ob.Stream.TLSSettings != nil {
		t := ob.Stream.TLSSettings
		if sni := orDefault(t.SNI, t.ServerName); sni != "" {
			q.Set("sni", sni)
		}
		if len(t.ALPN) > 0 {
			q.Set("alpn", strings.Join(t.ALPN, ","))
		}
		if t.AllowInsecure {
			q.Set("insecure", "1")
		}
	}
	if hs != nil && hs.Obfs != "" {
		q.Set("obfs", "salamander")
		q.Set("obfs-password", hs.Obfs)
	}

	u := url.URL{
		Scheme:   "hysteria2",
		User:     url.User(password),
		Host:     hostPort(s.Address, s.Port),
		RawQuery: q.Encode(),
		Fragment: ob.Tag,
	}
	return u.String(), true
}

// xrayVMess rebuilds a vmess://base64(JSON) link (v2rayN field names) so the
// existing decodeVmess/VmessSingbox path does the heavy lifting. This is the
// most faithful round-trip for vmess, whose share-link IS a base64 JSON blob.
func xrayVMess(ob *xrayOutbound) (string, bool) {
	var s vnextSettings
	if err := json.Unmarshal(ob.Settings, &s); err != nil || len(s.Vnext) == 0 || len(s.Vnext[0].Users) == 0 {
		skip("vmess", "missing vnext/users")
		return "", false
	}
	srv := s.Vnext[0]
	usr := srv.Users[0]

	// v2rayN vmess JSON. Keys VmessSingbox/decodeVmess consume: add, port, id,
	// aid, scy, net, type, host, path, tls, sni, alpn, fp, ps.
	m := map[string]interface{}{
		"v":    "2",
		"ps":   ob.Tag,
		"add":  srv.Address,
		"port": strconv.Itoa(srv.Port),
		"id":   usr.ID,
		"aid":  numToString(usr.AlterID),
		"scy":  orDefault(usr.Security, "auto"),
	}

	applyStreamToVmessMap(m, ob.Stream)

	jsonBytes, err := json.Marshal(m)
	if err != nil {
		skip("vmess", "could not marshal rebuilt vmess JSON: "+err.Error())
		return "", false
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(jsonBytes), true
}

// applyStreamToQuery fills share-link query params (type=, security=, sni=,
// host=, path=, alpn=, fp=, pbk=, sid=, serviceName=, mode=, allowInsecure=)
// from an Xray streamSettings block. Used by vless/trojan (and shadowsocks does
// not carry a stream). Best-effort: unknown networks fall through as type=<net>
// and let the URI transport parser decide (it handles tcp/ws/grpc/http/
// httpupgrade/xhttp/quic and errors on truly unknown types, which keeps a bad
// node out instead of crashing the import).
func applyStreamToQuery(q url.Values, st *xrayStream) {
	if st == nil {
		return
	}
	net := normalizeNetwork(st.Network)
	if net != "" {
		q.Set("type", net)
	}

	switch strings.ToLower(st.Security) {
	case "tls":
		q.Set("security", "tls")
	case "reality":
		q.Set("security", "reality")
	case "none", "":
		// leave unset
	default:
		q.Set("security", st.Security)
	}

	if st.TLSSettings != nil {
		t := st.TLSSettings
		if sni := orDefault(t.SNI, t.ServerName); sni != "" {
			q.Set("sni", sni)
		}
		if len(t.ALPN) > 0 {
			q.Set("alpn", strings.Join(t.ALPN, ","))
		}
		if t.Fingerprint != "" {
			q.Set("fp", t.Fingerprint)
		}
		if t.AllowInsecure {
			q.Set("allowInsecure", "1")
		}
	}

	if st.RealitySettings != nil {
		r := st.RealitySettings
		if sni := orDefault(r.SNI, r.ServerName); sni != "" {
			q.Set("sni", sni)
		}
		if r.PublicKey != "" {
			q.Set("pbk", r.PublicKey)
		}
		if sid := orDefault(r.ShortID, r.ShortIDAlt); sid != "" {
			q.Set("sid", sid)
		}
		if r.SpiderX != "" {
			q.Set("spx", r.SpiderX)
		}
		if r.Fingerprint != "" {
			q.Set("fp", r.Fingerprint)
		}
	}

	applyNetworkParamsToQuery(q, net, st)
}

// applyNetworkParamsToQuery sets transport-specific query params (path/host/
// serviceName/mode) based on the resolved network.
func applyNetworkParamsToQuery(q url.Values, net string, st *xrayStream) {
	switch net {
	case "ws", "httpupgrade":
		ws := st.WSSettings
		if net == "httpupgrade" && st.HTTPUpgrade != nil {
			ws = st.HTTPUpgrade
		}
		if ws != nil {
			if ws.Path != "" {
				q.Set("path", ws.Path)
			}
			if h := wsHost(ws); h != "" {
				q.Set("host", h)
			}
		}
	case "grpc":
		if st.GRPCSettings != nil && st.GRPCSettings.ServiceName != "" {
			q.Set("serviceName", st.GRPCSettings.ServiceName)
		}
	case "http", "h2":
		if st.HTTPSettings != nil {
			if st.HTTPSettings.Path != "" {
				q.Set("path", st.HTTPSettings.Path)
			}
			if len(st.HTTPSettings.Host) > 0 {
				q.Set("host", strings.Join(st.HTTPSettings.Host, ","))
			}
		}
	case "xhttp", "splithttp":
		x := st.XHTTPSettings
		if x == nil {
			x = st.SplitHTTP
		}
		if x != nil {
			if x.Path != "" {
				q.Set("path", x.Path)
			}
			if x.Host != "" {
				q.Set("host", x.Host)
			}
			if x.Mode != "" {
				q.Set("mode", x.Mode)
			}
			// Пробрасываем полный объект настроек как `extra`.
			//
			// getTransportOptions разбирает decoded["extra"] в XHTTPExtra (а тот —
			// в V2RayXHTTPBaseOptions + downloadSettings), то есть `extra` у нас и
			// есть канал для ВСЕГО, что не влезает в query-параметры ссылки.
			//
			// Семантика повторяет Xray (SplitHTTPConfig.Build): если `extra` задан
			// явно — он и есть полный конфиг, top-level поля-соседи отбрасываются
			// (у Xray `c = &extra`); если не задан — полным конфигом является сам
			// объект настроек. host/path/mode в обоих случаях приезжают отдельными
			// query-параметрами и перекрывают extra на стороне парсера (common.go).
			//
			// InHive 2026-07-19: раньше при отсутствии `extra` терялись ВСЕ
			// остальные top-level поля (xmux, downloadSettings, sc*, headers,
			// noGRPCHeader, uplinkHTTPMethod, obfs-набор) — см. UnmarshalJSON выше.
			switch {
			case len(x.Extra) > 0:
				q.Set("extra", string(x.Extra))
			case len(x.raw) > 0:
				q.Set("extra", string(x.raw))
			}
		}
	case "tcp":
		// TCP HTTP-header obfuscation (tcpSettings.header.type=http). Promote to the
		// http transport via headerType=http (common.go:208), consistent with the
		// share-link path. Xray stores request path & Host as ARRAYS — take element [0].
		// Plain TCP (no http header) leaves the query untouched → byte-identical. (Audit 2026-06-26.)
		if t := st.TCPSettings; t != nil && strings.EqualFold(t.Header.Type, "http") {
			q.Set("headerType", "http")
			if p := t.Header.Request.Path; len(p) > 0 && p[0] != "" {
				q.Set("path", p[0])
			}
			if h := t.Header.Request.Headers["Host"]; len(h) > 0 && h[0] != "" {
				q.Set("host", h[0])
			}
		}
	}
}

// applyStreamToVmessMap fills the v2rayN vmess JSON map from streamSettings.
// vmess uses the legacy field spellings (net/type/host/path/tls/sni/alpn/fp).
func applyStreamToVmessMap(m map[string]interface{}, st *xrayStream) {
	if st == nil {
		m["net"] = "tcp"
		return
	}
	net := normalizeNetwork(st.Network)
	if net == "" {
		net = "tcp"
	}
	m["net"] = net

	switch strings.ToLower(st.Security) {
	case "tls":
		m["tls"] = "tls"
	case "reality":
		// vmess+reality is rare but the shared getTLSOptions handles tls=reality.
		m["tls"] = "reality"
	}

	if st.TLSSettings != nil {
		t := st.TLSSettings
		if sni := orDefault(t.SNI, t.ServerName); sni != "" {
			m["sni"] = sni
		}
		if len(t.ALPN) > 0 {
			m["alpn"] = strings.Join(t.ALPN, ",")
		}
		if t.Fingerprint != "" {
			m["fp"] = t.Fingerprint
		}
	}
	if st.RealitySettings != nil {
		r := st.RealitySettings
		if sni := orDefault(r.SNI, r.ServerName); sni != "" {
			m["sni"] = sni
		}
		if r.PublicKey != "" {
			m["pbk"] = r.PublicKey
		}
		if sid := orDefault(r.ShortID, r.ShortIDAlt); sid != "" {
			m["sid"] = sid
		}
		if r.Fingerprint != "" {
			m["fp"] = r.Fingerprint
		}
	}

	switch net {
	case "ws", "httpupgrade":
		ws := st.WSSettings
		if net == "httpupgrade" && st.HTTPUpgrade != nil {
			ws = st.HTTPUpgrade
		}
		if ws != nil {
			if ws.Path != "" {
				m["path"] = ws.Path
			}
			if h := wsHost(ws); h != "" {
				m["host"] = h
			}
		}
	case "grpc":
		if st.GRPCSettings != nil && st.GRPCSettings.ServiceName != "" {
			m["path"] = st.GRPCSettings.ServiceName
		}
	case "http", "h2":
		if st.HTTPSettings != nil {
			if st.HTTPSettings.Path != "" {
				m["path"] = st.HTTPSettings.Path
			}
			if len(st.HTTPSettings.Host) > 0 {
				m["host"] = strings.Join(st.HTTPSettings.Host, ",")
			}
		}
	case "xhttp", "splithttp":
		x := st.XHTTPSettings
		if x == nil {
			x = st.SplitHTTP
		}
		if x != nil {
			if x.Path != "" {
				m["path"] = x.Path
			}
			if x.Host != "" {
				m["host"] = x.Host
			}
		}
	case "tcp":
		// vmess+tcp HTTP-header obfs (classic v2ray): the header type lives in the
		// vmess `type` field; common.go:208 promotes net=tcp+type=http to the http
		// transport. Xray stores path & Host as arrays — take element [0]. Previously
		// the dead TCPSettings map dropped this silently. (Audit 2026-06-26.)
		if t := st.TCPSettings; t != nil && strings.EqualFold(t.Header.Type, "http") {
			m["type"] = "http"
			if p := t.Header.Request.Path; len(p) > 0 && p[0] != "" {
				m["path"] = p[0]
			}
			if h := t.Header.Request.Headers["Host"]; len(h) > 0 && h[0] != "" {
				m["host"] = h[0]
			}
		}
	}
}

// ---------------------------------------------------------------------------
// SIP008 server object -> ss:// URI
// ---------------------------------------------------------------------------

// uriFromSIP008 converts one SIP008 server entry to a SIP002 ss:// URI.
// SIP008 fields: server, server_port, method, password, remarks/name, plugin,
// plugin_opts.
func uriFromSIP008(raw json.RawMessage) (string, bool) {
	var s struct {
		Server     string      `json:"server"`
		ServerPort json.Number `json:"server_port"`
		Method     string      `json:"method"`
		Password   string      `json:"password"`
		Remarks    string      `json:"remarks"`
		Name       string      `json:"name"`
		Plugin     string      `json:"plugin"`
		PluginOpts string      `json:"plugin_opts"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		skip("sip008", "server object did not unmarshal: "+err.Error())
		return "", false
	}
	if s.Server == "" || s.Method == "" {
		skip("sip008", "missing server/method")
		return "", false
	}
	port := 0
	if p, err := s.ServerPort.Int64(); err == nil {
		port = int(p)
	}
	plugin := s.Plugin
	if plugin != "" && s.PluginOpts != "" {
		// SIP002 plugin param: "name;opts". ShadowsocksSingbox splits on the
		// first unescaped ';'.
		plugin = plugin + ";" + s.PluginOpts
	}
	return buildSSURI(s.Method, s.Password, s.Server, port, orDefault(s.Remarks, s.Name), plugin), true
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// buildSSURI builds a SIP002 ss:// URI: ss://base64url(method:password)@host:port?plugin=...#name
// userinfo is base64url(no padding) of "method:password" — the form
// ShadowsocksSingbox/ParseUrl decode. Plugin (already "name;opts") goes in the
// query.
func buildSSURI(method, password, host string, port int, name, plugin string) string {
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
	var b strings.Builder
	b.WriteString("ss://")
	b.WriteString(userinfo)
	b.WriteString("@")
	b.WriteString(hostPort(host, port))
	if plugin != "" {
		q := url.Values{}
		q.Set("plugin", plugin)
		b.WriteString("?")
		b.WriteString(q.Encode())
	}
	if name != "" {
		b.WriteString("#")
		b.WriteString(url.PathEscape(name))
	}
	return b.String()
}

// hostPort joins host:port, bracketing IPv6 literals so net/url parses them.
func hostPort(host string, port int) string {
	if port == 0 {
		port = 443
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(port)
}

// normalizeNetwork maps Xray network spellings onto the values the existing
// transport parser (getTransportOptions) understands. It leaves the heavy
// lifting (h2->http, splithttp->xhttp, raw->tcp) to that parser, but folds the
// obvious aliases here so the query/vmess map is clean.
func normalizeNetwork(n string) string {
	switch strings.ToLower(strings.TrimSpace(n)) {
	case "", "raw", "tcp", "none":
		return "tcp"
	case "ws", "websocket":
		return "ws"
	case "httpupgrade":
		return "httpupgrade"
	case "grpc", "gun":
		return "grpc"
	case "h2", "http":
		return "http"
	case "quic":
		return "quic"
	case "xhttp", "splithttp":
		return "xhttp"
	default:
		return strings.ToLower(strings.TrimSpace(n))
	}
}

// wsHost extracts the WS Host: from either the dedicated host field or a
// Headers["Host"] entry (v2ray puts it in headers, some panels in host).
func wsHost(ws *xrayWSSettings) string {
	if ws.Host != "" {
		return ws.Host
	}
	if ws.Headers != nil {
		if h, ok := ws.Headers["Host"]; ok {
			return h
		}
		if h, ok := ws.Headers["host"]; ok {
			return h
		}
	}
	return ""
}

func orDefault(v, def string) string {
	if v != "" {
		return v
	}
	return def
}

func numToString(n json.Number) string {
	s := string(n)
	if s == "" {
		return "0"
	}
	return s
}

// skip logs a non-fatal warning that one entry was dropped, mirroring the
// per-config error logging in GenerateConfigLite (stderr). The import
// continues with the remaining entries.
func skip(protocol, reason string) {
	fmt.Fprintf(os.Stderr, "[xray2sing/json] skipping %s entry: %s\n", protocol, reason)
}
