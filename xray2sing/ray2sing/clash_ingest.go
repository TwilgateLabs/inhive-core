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
	"fmt"
	"net/url"
	"sort"
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
	// h2-opts / http-opts were not modelled at all, so `network: h2` and
	// `network: http` nodes lost their Host list and path: the transport was
	// still built, but as http with path "/" against the origin's default vhost.
	// On a CDN-fronted node that is a 404 on every request with no client-side
	// error. (2026-07-19.)
	H2Opts   *clashH2Opts   `yaml:"h2-opts"`
	HTTPOpts *clashHTTPOpts `yaml:"http-opts"`
	// xhttp is NOT an upstream mihomo key — mihomo has no xhttp transport. It is
	// accepted here because panel-side YAML generators (x-ui / marzban dialects)
	// do emit it, and the universal-client invariant says a foreign subscription
	// must not silently lose a node. Absent in a normal Clash file => no effect.
	XHTTPOpts map[string]any `yaml:"xhttp-opts"`

	// Shadowsocks SIP003 plugin (obfs / v2ray-plugin / shadow-tls / restls).
	// Was dropped entirely: an obfs-wrapped SS node came out as bare SS, which
	// the server rejects — the classic "works in Clash, dead in ours" report.
	Plugin     string         `yaml:"plugin"`
	PluginOpts map[string]any `yaml:"plugin-opts"`

	ECHOpts *clashECHOpts `yaml:"ech-opts"`

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

// clashH2Opts / clashHTTPOpts — mihomo's HTTP/2 and HTTP-obfs transport blocks.
// Both spell host as a LIST (rotation); http-opts additionally carries method
// and a multi-value header map.
type clashH2Opts struct {
	Host []string `yaml:"host"`
	Path string   `yaml:"path"`
}

type clashHTTPOpts struct {
	Method  string              `yaml:"method"`
	Path    []string            `yaml:"path"`
	Headers map[string][]string `yaml:"headers"`
}

type clashECHOpts struct {
	Enable bool   `yaml:"enable"`
	Config string `yaml:"config"`
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
	case "h2":
		// getTransportOptions folds h2 -> the http transport and splits a
		// comma-separated host into the Host LIST, so join mihomo's list here.
		if p.H2Opts != nil {
			if p.H2Opts.Path != "" {
				q.Set("path", p.H2Opts.Path)
			}
			if len(p.H2Opts.Host) > 0 {
				q.Set("host", strings.Join(p.H2Opts.Host, ","))
			}
		}
	case "http":
		// mihomo's `network: http` is TCP + HTTP/1.1 header obfuscation, the same
		// thing Xray spells tcpSettings.header.type=http — hence headerType=http,
		// which common.go promotes to the http transport.
		q.Set("type", "tcp")
		q.Set("headerType", "http")
		if p.HTTPOpts != nil {
			if len(p.HTTPOpts.Path) > 0 && p.HTTPOpts.Path[0] != "" {
				q.Set("path", p.HTTPOpts.Path[0])
			}
			if p.HTTPOpts.Method != "" {
				q.Set("method", p.HTTPOpts.Method)
			}
			if h := p.HTTPOpts.Headers["Host"]; len(h) > 0 && h[0] != "" {
				q.Set("host", h[0])
			}
			if hdrs := clashSingleValueHeaders(p.HTTPOpts.Headers); len(hdrs) > 0 {
				if b, err := json.Marshal(hdrs); err == nil {
					q.Set("headers", string(b))
				}
			}
		}
	case "xhttp", "splithttp":
		// Not an upstream mihomo transport (see clashProxy.XHTTPOpts). Forward
		// the block verbatim through `extra`, the same channel the Xray/sing-box
		// JSON paths use, and lift host/path/mode to top level where they win.
		if len(p.XHTTPOpts) == 0 {
			return
		}
		if v, ok := p.XHTTPOpts["path"].(string); ok && v != "" {
			q.Set("path", v)
		}
		if v, ok := p.XHTTPOpts["host"].(string); ok && v != "" {
			q.Set("host", v)
		}
		if v, ok := p.XHTTPOpts["mode"].(string); ok && v != "" {
			q.Set("mode", v)
		}
		if b, err := json.Marshal(p.XHTTPOpts); err == nil {
			q.Set("extra", string(b))
		}
	}
}

// clashSingleValueHeaders flattens mihomo's multi-value header map to the
// single-value form the `headers` query key carries (Host travels as host=).
func clashSingleValueHeaders(h map[string][]string) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		if strings.EqualFold(k, "Host") || len(v) == 0 || v[0] == "" {
			continue
		}
		out[k] = v[0]
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
	// ech-opts was not read, so a Clash node with Encrypted Client Hello lost it
	// and sent its SNI in plaintext — no error, just the privacy property gone.
	// An enabled block with no inline config degrades to sing-box's DNS HTTPS-RR
	// fetch (ECH stays on), matching the rest of the ingest paths. (2026-07-19.)
	if p.ECHOpts != nil && p.ECHOpts.Enable {
		q.Set("ech", p.ECHOpts.Config)
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
	// The SIP003 plugin was dropped here: an obfs / v2ray-plugin wrapped node was
	// rebuilt as BARE shadowsocks. It parses, it builds, and then every packet is
	// rejected by a server that expects the obfuscation layer — silent-fail with
	// no diagnostic. buildSSURI emits the SIP002 `plugin=name;opts` form that
	// ShadowsocksSingbox already understands. (2026-07-19.)
	return buildSSURI(p.Cipher, p.Password, p.Server, p.Port, p.Name, clashPluginParam(p)), true
}

// clashPluginParam renders mihomo's plugin + plugin-opts map as the SIP002
// "name;k=v;k=v" plugin parameter. mode/host/path/tls are the keys the obfs and
// v2ray-plugin implementations actually read; `mux` and unknown keys pass through
// so a plugin we do not model still receives its options verbatim.
func clashPluginParam(p *clashProxy) string {
	if p.Plugin == "" {
		return ""
	}
	name := p.Plugin
	if name == "obfs" {
		name = "obfs-local" // SIP002 spells the simple-obfs client this way
	}
	if len(p.PluginOpts) == 0 {
		return name
	}
	parts := make([]string, 0, len(p.PluginOpts)+1)
	parts = append(parts, name)
	// Deterministic order — this string ends up inside a URI that tests compare.
	keys := make([]string, 0, len(p.PluginOpts))
	for k := range p.PluginOpts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := p.PluginOpts[k]
		if b, ok := v.(bool); ok {
			if b {
				parts = append(parts, k)
			}
			continue
		}
		parts = append(parts, k+"="+fmt.Sprintf("%v", v))
	}
	return strings.Join(parts, ";")
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
	// Same divergence the sing-box branch had: vmess hand-rolled a smaller
	// mapping than vless/trojan and therefore lost skip-cert-verify,
	// client-fingerprint and reality-opts (plus every transport beyond ws/grpc).
	// Effects, in order of damage: reality dropped => plain-TLS handshake against
	// a REALITY server fails; client-fingerprint dropped => vmess.go substitutes
	// chrome, replacing the ClientHello signature the operator chose;
	// skip-cert-verify dropped => verification is stricter than configured, so a
	// self-signed node fails closed (dead node, not a weakened one).
	// Now routed through the SAME appliers as vless/trojan. (2026-07-19.)
	q := url.Values{}
	applyClashTransport(q, p)
	applyClashTLS(q, p, false)
	mergeQueryIntoVmessMap(m, q)
	if p.Network == "grpc" && p.GRPCOpts != nil && p.GRPCOpts.ServiceName != "" {
		m["path"] = p.GRPCOpts.ServiceName // legacy vmess carries serviceName in path
	}
	b, err := json.Marshal(m)
	if err != nil {
		skip("vmess", "clash marshal: "+err.Error())
		return "", false
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(b), true
}
