// clash_ingest.go — Clash / Clash.Meta YAML subscription -> share-link URIs.
//
// Clash YAML is one of the two dominant subscription formats (providers serve it
// to clients presenting as clash). A top-level `proxies:` list of typed maps;
// field names differ from sing-box/Xray (port, cipher, servername,
// skip-cert-verify, network + ws-opts/grpc-opts, reality-opts). Same contract as
// the JSON ingest: rebuild each proxy to a canonical share-link and feed the
// single per-protocol parser pipeline, so list/ping/connect stay one source.
//
// yaml.v3 is already in the module graph (indirect via sing-box) — no new dep.

package ray2sing

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type clashDoc struct {
	Proxies []clashProxy `yaml:"proxies"`
}

type clashProxy struct {
	Name           string   `yaml:"name"`
	Type           string   `yaml:"type"`
	Server         string   `yaml:"server"`
	Port           int      `yaml:"port"`
	UUID           string   `yaml:"uuid"`
	Password       string   `yaml:"password"`
	Cipher         string   `yaml:"cipher"` // ss method / vmess cipher
	AlterID        int      `yaml:"alterId"`
	Flow           string   `yaml:"flow"`
	TLS            bool     `yaml:"tls"`
	SNI            string   `yaml:"sni"`
	Servername     string   `yaml:"servername"` // vless sni
	SkipCertVerify bool     `yaml:"skip-cert-verify"`
	ALPN           []string `yaml:"alpn"`
	Fingerprint    string   `yaml:"client-fingerprint"`
	Network        string   `yaml:"network"`

	WSOpts      *clashWSOpts      `yaml:"ws-opts"`
	GRPCOpts    *clashGRPCOpts    `yaml:"grpc-opts"`
	RealityOpts *clashRealityOpts `yaml:"reality-opts"`

	Obfs         string `yaml:"obfs"`          // hysteria2
	ObfsPassword string `yaml:"obfs-password"` // hysteria2

	CongestionController string `yaml:"congestion-controller"` // tuic
	UDPRelayMode         string `yaml:"udp-relay-mode"`        // tuic
}

type clashWSOpts struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

type clashGRPCOpts struct {
	ServiceName string `yaml:"grpc-service-name"`
}

type clashRealityOpts struct {
	PublicKey string `yaml:"public-key"`
	ShortID   string `yaml:"short-id"`
}

// ingestClashYAML detects+transcodes a Clash YAML subscription. (joined links,
// true) on success; ("", false) otherwise so the caller falls through unchanged.
func ingestClashYAML(input string) (string, bool) {
	if !clashLooksLikeYAML(input) {
		return "", false
	}
	var doc clashDoc
	if err := yaml.Unmarshal([]byte(input), &doc); err != nil || len(doc.Proxies) == 0 {
		return "", false
	}
	var links []string
	for i := range doc.Proxies {
		if uri, ok := uriFromClashProxy(&doc.Proxies[i]); ok {
			links = append(links, uri)
		}
	}
	if len(links) == 0 {
		return "", false
	}
	return strings.Join(links, "\n"), true
}

// clashLooksLikeYAML is a cheap sniff (avoid paying for a full YAML parse on
// every share-link sub): a Clash config always has a top-level `proxies:` key.
func clashLooksLikeYAML(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "proxies:") {
			return true
		}
	}
	return false
}

func uriFromClashProxy(p *clashProxy) (string, bool) {
	if p.Server == "" || p.Port == 0 {
		skip(p.Type, "clash proxy has no server/port")
		return "", false
	}
	switch strings.ToLower(p.Type) {
	case "hysteria2", "hy2":
		return clashHysteria2(p)
	case "vless":
		return clashVLESS(p)
	case "vmess":
		return clashVMess(p)
	case "trojan":
		return clashTrojan(p)
	case "ss", "shadowsocks":
		return clashShadowsocks(p)
	case "tuic":
		return clashTUIC(p)
	default:
		skip(p.Type, "clash proxy type not rebuilt to a share-link (skipped, not fatal)")
		return "", false
	}
}

func clashSNI(p *clashProxy) string {
	if p.Servername != "" {
		return p.Servername
	}
	return p.SNI
}

func applyClashTransport(q url.Values, p *clashProxy) {
	net := p.Network
	if net == "" {
		net = "tcp"
	}
	q.Set("type", net)
	switch net {
	case "ws", "httpupgrade":
		if p.WSOpts != nil {
			if p.WSOpts.Path != "" {
				q.Set("path", p.WSOpts.Path)
			}
			if h := p.WSOpts.Headers["Host"]; h != "" {
				q.Set("host", h)
			}
		}
	case "grpc":
		if p.GRPCOpts != nil && p.GRPCOpts.ServiceName != "" {
			q.Set("serviceName", p.GRPCOpts.ServiceName)
		}
	}
}

func applyClashTLS(q url.Values, p *clashProxy, tlsImplied bool) {
	tlsOn := p.TLS || tlsImplied
	if p.RealityOpts != nil && p.RealityOpts.PublicKey != "" {
		q.Set("security", "reality")
		q.Set("pbk", p.RealityOpts.PublicKey)
		if p.RealityOpts.ShortID != "" {
			q.Set("sid", p.RealityOpts.ShortID)
		}
		tlsOn = true
	} else if tlsOn {
		q.Set("security", "tls")
	} else {
		q.Set("security", "none")
	}
	if !tlsOn {
		return
	}
	if sni := clashSNI(p); sni != "" {
		q.Set("sni", sni)
	}
	if len(p.ALPN) > 0 {
		q.Set("alpn", strings.Join(p.ALPN, ","))
	}
	if p.Fingerprint != "" {
		q.Set("fp", p.Fingerprint)
	}
	if p.SkipCertVerify {
		q.Set("insecure", "1")
		q.Set("allowInsecure", "1")
	}
}

func clashHysteria2(p *clashProxy) (string, bool) {
	q := url.Values{}
	if sni := clashSNI(p); sni != "" {
		q.Set("sni", sni)
	}
	if len(p.ALPN) > 0 {
		q.Set("alpn", strings.Join(p.ALPN, ","))
	}
	if p.SkipCertVerify {
		q.Set("insecure", "1")
	}
	if p.Obfs != "" {
		q.Set("obfs", p.Obfs)
		if p.ObfsPassword != "" {
			q.Set("obfs-password", p.ObfsPassword)
		}
	}
	u := url.URL{Scheme: "hysteria2", User: url.User(p.Password), Host: hostPort(p.Server, p.Port), RawQuery: q.Encode(), Fragment: p.Name}
	return u.String(), true
}

func clashVLESS(p *clashProxy) (string, bool) {
	if p.UUID == "" {
		skip("vless", "clash: no uuid")
		return "", false
	}
	q := url.Values{}
	q.Set("encryption", "none")
	if p.Flow != "" {
		q.Set("flow", p.Flow)
	}
	applyClashTransport(q, p)
	applyClashTLS(q, p, false)
	u := url.URL{Scheme: "vless", User: url.User(p.UUID), Host: hostPort(p.Server, p.Port), RawQuery: q.Encode(), Fragment: p.Name}
	return u.String(), true
}

func clashTrojan(p *clashProxy) (string, bool) {
	if p.Password == "" {
		skip("trojan", "clash: no password")
		return "", false
	}
	q := url.Values{}
	applyClashTransport(q, p)
	applyClashTLS(q, p, true) // trojan is TLS-by-spec
	u := url.URL{Scheme: "trojan", User: url.User(p.Password), Host: hostPort(p.Server, p.Port), RawQuery: q.Encode(), Fragment: p.Name}
	return u.String(), true
}

func clashShadowsocks(p *clashProxy) (string, bool) {
	if p.Cipher == "" {
		skip("shadowsocks", "clash: no cipher")
		return "", false
	}
	userinfo := base64.RawURLEncoding.EncodeToString([]byte(p.Cipher + ":" + p.Password))
	u := url.URL{Scheme: "ss", User: url.User(userinfo), Host: hostPort(p.Server, p.Port), Fragment: p.Name}
	return u.String(), true
}

func clashTUIC(p *clashProxy) (string, bool) {
	if p.UUID == "" {
		skip("tuic", "clash: no uuid")
		return "", false
	}
	q := url.Values{}
	if p.CongestionController != "" {
		q.Set("congestion_control", p.CongestionController)
	}
	if p.UDPRelayMode != "" {
		q.Set("udp_relay_mode", p.UDPRelayMode)
	}
	if sni := clashSNI(p); sni != "" {
		q.Set("sni", sni)
	}
	if len(p.ALPN) > 0 {
		q.Set("alpn", strings.Join(p.ALPN, ","))
	}
	if p.SkipCertVerify {
		q.Set("allow_insecure", "1")
	}
	u := url.URL{Scheme: "tuic", User: url.UserPassword(p.UUID, p.Password), Host: hostPort(p.Server, p.Port), RawQuery: q.Encode(), Fragment: p.Name}
	return u.String(), true
}

func clashVMess(p *clashProxy) (string, bool) {
	if p.UUID == "" {
		skip("vmess", "clash: no uuid")
		return "", false
	}
	m := map[string]string{
		"v": "2", "ps": p.Name, "add": p.Server, "port": strconv.Itoa(p.Port),
		"id": p.UUID, "aid": strconv.Itoa(p.AlterID), "scy": orDefault(p.Cipher, "auto"),
		"net": orDefault(p.Network, "tcp"), "type": "none",
	}
	if p.Network == "ws" && p.WSOpts != nil {
		if p.WSOpts.Path != "" {
			m["path"] = p.WSOpts.Path
		}
		if h := p.WSOpts.Headers["Host"]; h != "" {
			m["host"] = h
		}
	}
	if p.Network == "grpc" && p.GRPCOpts != nil && p.GRPCOpts.ServiceName != "" {
		m["path"] = p.GRPCOpts.ServiceName
	}
	if p.TLS {
		m["tls"] = "tls"
		if sni := clashSNI(p); sni != "" {
			m["sni"] = sni
		}
		if len(p.ALPN) > 0 {
			m["alpn"] = strings.Join(p.ALPN, ",")
		}
	}
	b, err := json.Marshal(m)
	if err != nil {
		skip("vmess", "clash marshal: "+err.Error())
		return "", false
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b), true
}
