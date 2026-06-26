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

type singboxTLS struct {
	Enabled    bool     `json:"enabled"`
	ServerName string   `json:"server_name"`
	Insecure   bool     `json:"insecure"`
	ALPN       []string `json:"alpn"`
	UTLS       *struct {
		Enabled     bool   `json:"enabled"`
		Fingerprint string `json:"fingerprint"`
	} `json:"utls"`
	Reality *struct {
		Enabled   bool   `json:"enabled"`
		PublicKey string `json:"public_key"`
		ShortID   string `json:"short_id"`
	} `json:"reality"`
}

type singboxTransport struct {
	Type        string            `json:"type"` // ws / grpc / http / httpupgrade
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers"`      // Host etc.
	ServiceName string            `json:"service_name"` // grpc
	Host        json.RawMessage   `json:"host"`         // http: string OR []string
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
}

// applySingboxTransport writes net/path/host/serviceName from a sing-box
// transport block (default tcp when absent).
func applySingboxTransport(q url.Values, tr *singboxTransport) {
	if tr == nil || tr.Type == "" {
		q.Set("type", "tcp")
		return
	}
	q.Set("type", tr.Type)
	switch tr.Type {
	case "ws", "httpupgrade":
		if tr.Path != "" {
			q.Set("path", tr.Path)
		}
		if h := tr.Headers["Host"]; h != "" {
			q.Set("host", h)
		}
	case "grpc":
		if tr.ServiceName != "" {
			q.Set("serviceName", tr.ServiceName)
		}
	case "http":
		if tr.Path != "" {
			q.Set("path", tr.Path)
		}
		if len(tr.Host) > 0 {
			var hs []string
			if err := json.Unmarshal(tr.Host, &hs); err == nil && len(hs) > 0 {
				q.Set("host", strings.Join(hs, ","))
			} else {
				var h string
				if json.Unmarshal(tr.Host, &h) == nil && h != "" {
					q.Set("host", h)
				}
			}
		}
	}
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
	if tr := ob.Transport; tr != nil && tr.Type != "" {
		m["net"] = tr.Type
		if tr.Path != "" {
			m["path"] = tr.Path
		}
		if h := tr.Headers["Host"]; h != "" {
			m["host"] = h
		}
		if tr.ServiceName != "" {
			m["path"] = tr.ServiceName // grpc carries serviceName in path
		}
	}
	if ob.TLS != nil && ob.TLS.Enabled {
		m["tls"] = "tls"
		if ob.TLS.ServerName != "" {
			m["sni"] = ob.TLS.ServerName
		}
		if len(ob.TLS.ALPN) > 0 {
			m["alpn"] = strings.Join(ob.TLS.ALPN, ",")
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		skip("vmess", "marshal: "+err.Error())
		return "", false
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b), true
}
