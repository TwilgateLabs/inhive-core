package ray2sing_test

// compat_corpus_test.go — the PERMANENT compatibility guard.
//
// Born 2026-06-26 after the third "our universal client doesn't support config
// class X" regression. Root cause of the recurrence was a METHOD gap: acceptance
// was "the config parsed without error" instead of "the produced sing-box outbound
// is semantically what Xray/Happ produces". 11 of 14 audit bugs were silent-fail:
// a valid outbound that doesn't carry traffic (or carries it insecurely).
//
// This file is the answer: one canonical URI/JSON per matrix cell (and one per
// fixed bug), each asserting the SPECIFIC outbound fields that must hold — plus a
// byte-identity sibling so a fix can't regress the untouched path. If a future
// change re-breaks a class, THIS test goes red, not Никита.
//
// Adding a protocol/transport/TLS combo = add a row here. A cell with no row is an
// untested cell.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/twilgate/xray2sing/ray2sing"
)

// urlQueryEscape percent-encodes a value for use inside a share-link query string.
func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// firstOutbound parses one config (share-link URI or JSON) through the full
// ray2sing pipeline and returns the first outbound as a generic map.
func firstOutbound(t *testing.T, config string) (map[string]any, error) {
	t.Helper()
	out, err := ray2sing.Ray2Singbox(context.Background(), config, false)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal produced config: %v\n%s", err, out)
	}
	if len(doc.Outbounds) == 0 {
		t.Fatalf("no outbounds produced for: %s", config)
	}
	return doc.Outbounds[0], nil
}

// mustOutbound is firstOutbound but fails the test on a parse error.
func mustOutbound(t *testing.T, config string) map[string]any {
	t.Helper()
	ob, err := firstOutbound(t, config)
	if err != nil {
		t.Fatalf("parse error for %s: %v", config, err)
	}
	return ob
}

// outboundCount returns how many outbounds the pipeline produced. A node that
// errors during construction is dropped (logged, not built) — so a guard that
// rejects an unsupported variant manifests as count 0, NOT a top-level error
// (one bad node must never fail the whole subscription import).
func outboundCount(t *testing.T, config string) int {
	t.Helper()
	out, err := ray2sing.Ray2Singbox(context.Background(), config, false)
	if err != nil {
		return 0
	}
	var doc struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return 0
	}
	return len(doc.Outbounds)
}

func sub(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

// asStrings normalizes a sing-box Listable field (string OR []any) to []string.
func asStrings(v any) []string {
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// --- The corpus -----------------------------------------------------------

const corpusUUID = "11111111-2222-3333-4444-555555555555"

// #7 — h2/http multi-host must split into a Host LIST, not one bogus element.
func TestCorpus_H2MultiHostSplit(t *testing.T) {
	// vmess h2, host="a.example.com,b.example.com"
	multi := "vmess://eyJ2IjoiMiIsInBzIjoiaDIiLCJhZGQiOiJjZG4uZXhhbXBsZS5jb20iLCJwb3J0IjoiNDQzIiwiaWQiOiJkNDNlZTVlMy0xYjA3LTU2ZDctYjJlYS04ZDIyYzQ0ZmRjNjYiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6ImgyIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiYS5leGFtcGxlLmNvbSxiLmV4YW1wbGUuY29tIiwicGF0aCI6Ii9yYXkiLCJ0bHMiOiJ0bHMiLCJzbmkiOiJjZG4uZXhhbXBsZS5jb20ifQ=="
	ob := mustOutbound(t, multi)
	tr := sub(ob, "transport")
	if tr == nil || tr["type"] != "http" {
		t.Fatalf("transport type: got %v, want http", tr["type"])
	}
	hosts := asStrings(tr["host"])
	if !eqStrings(hosts, []string{"a.example.com", "b.example.com"}) {
		t.Errorf("host = %v, want [a.example.com b.example.com] (no literal comma)", hosts)
	}

	// sibling: single host stays a single element (byte-identity guard).
	single := "vmess://eyJ2IjoiMiIsInBzIjoiMSIsImFkZCI6ImNkbi5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6ImQ0M2VlNWUzLTFiMDctNTZkNy1iMmVhLThkMjJjNDRmZGM2NiIsImFpZCI6IjAiLCJuZXQiOiJoMiIsImhvc3QiOiJhLmV4YW1wbGUuY29tIiwicGF0aCI6Ii9yYXkiLCJ0bHMiOiJ0bHMifQ=="
	ob2 := mustOutbound(t, single)
	hosts2 := asStrings(sub(ob2, "transport")["host"])
	if !eqStrings(hosts2, []string{"a.example.com"}) {
		t.Errorf("single host = %v, want [a.example.com]", hosts2)
	}
}

// #8 — Trojan XTLS-Vision flow must be rejected with a diagnosable error, not
// silently built as plain Trojan-TLS.
func TestCorpus_TrojanVisionFlowRejected(t *testing.T) {
	// XTLS-Vision has no field in sing-box's Trojan options. The guard must REJECT
	// the node (dropped, with a logged error) rather than silently build a plain
	// Trojan-TLS node that dies in the handshake.
	withFlow := "trojan://pass123@example.com:443?security=tls&type=tcp&flow=xtls-rprx-vision&sni=example.com#node"
	if n := outboundCount(t, withFlow); n != 0 {
		t.Errorf("trojan flow=xtls-rprx-vision: built %d outbound(s), want 0 (rejected, not silently broken)", n)
	}
	// direct guard at the parser level: surfaced error mentions flow.
	if _, err := ray2sing.TrojanSingbox(withFlow); err == nil || !strings.Contains(strings.ToLower(err.Error()), "flow") {
		t.Errorf("TrojanSingbox should error mentioning flow, got: %v", err)
	}
	// sibling: same node without flow builds fine.
	noFlow := "trojan://pass123@example.com:443?security=tls&type=tcp&sni=example.com#node"
	if n := outboundCount(t, noFlow); n != 1 {
		t.Errorf("trojan without flow: built %d outbound(s), want 1", n)
	}
}

// #3 — SIP002 base64 userinfo with awkward password chars / url-safe alphabet
// must decode (not drop method to the raw blob).
func TestCorpus_SS_SIP002_Userinfo(t *testing.T) {
	cases := []struct{ name, uri string }{
		// base64("aes-256-gcm:p@ss.word") — the '.' broke the old isValidChar whitelist.
		{"password_with_dot", "ss://YWVzLTI1Ni1nY206cEBzcy53b3Jk@1.2.3.4:8388#node"},
		// base64url userinfo ('-' in the alphabet) — old base64CharRegex rejected it.
		{"base64url", "ss://YWVzLTI1Ni1nY206cGE-PndvcmQ=@1.2.3.4:8388#node"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ob := mustOutbound(t, c.uri)
			if ob["method"] != "aes-256-gcm" {
				t.Errorf("method = %v, want aes-256-gcm (SIP002 decode dropped)", ob["method"])
			}
			if pw, _ := ob["password"].(string); pw == "" || strings.Contains(pw, "aes-256-gcm") {
				t.Errorf("password = %q looks like the raw blob, not the decoded password", pw)
			}
		})
	}
	// SS-2022 regression guard: method preserved, PSK after first ':'.
	ob := mustOutbound(t, "ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206UEFTU1dPUkRiYXNlNjQ=@1.2.3.4:8388#node")
	if ob["method"] != "2022-blake3-aes-256-gcm" {
		t.Errorf("ss2022 method = %v, want 2022-blake3-aes-256-gcm", ob["method"])
	}
}

// #2 — TUIC must not force-disable SNI for a hostname endpoint (that breaks
// SNI-routing AND silently kills cert verification). Bare-IP endpoint still omits.
func TestCorpus_TUIC_SNI(t *testing.T) {
	host := mustOutbound(t, "tuic://b1d3a4e2-0000-4f5a-9c1d-aaaaaaaaaaaa:pw@cdn.example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3#node")
	tls := sub(host, "tls")
	if v, _ := tls["disable_sni"].(bool); v {
		t.Error("hostname TUIC endpoint: disable_sni=true (breaks SNI-routing + cert verification)")
	}
	if host["congestion_control"] != "bbr" {
		t.Errorf("congestion_control = %v, want bbr", host["congestion_control"])
	}
	// sibling: bare-IP endpoint with no sni= correctly disables SNI.
	ip := mustOutbound(t, "tuic://b1d3a4e2-0000-4f5a-9c1d-aaaaaaaaaaaa:pw@1.2.3.4:443?congestion_control=bbr&alpn=h3#node")
	if v, _ := sub(ip, "tls")["disable_sni"].(bool); !v {
		t.Error("bare-IP TUIC endpoint: disable_sni should be true")
	}
}

// #11 — https:// HTTP proxy insecure flag must parse secure-by-default
// (insecure=false → verify), not the old inverted "anything but 0 is insecure".
func TestCorpus_HTTPSProxyInsecure(t *testing.T) {
	verify := mustOutbound(t, "https://user:pass@proxy.example.com:443?insecure=false#node")
	if v, _ := sub(verify, "tls")["insecure"].(bool); v {
		t.Error("insecure=false must mean cert verification ON (insecure=false)")
	}
	skip := mustOutbound(t, "https://user:pass@proxy.example.com:443?insecure=1#node")
	if v, _ := sub(skip, "tls")["insecure"].(bool); !v {
		t.Error("insecure=1 must disable verification (insecure=true)")
	}
}

// #12 — Hysteria2 explicit alpn must be honored (was parsed then ignored).
func TestCorpus_Hysteria2_ALPN(t *testing.T) {
	ob := mustOutbound(t, "hysteria2://pass@example.com:443/?sni=example.com&alpn=h3,custom-alpn&insecure=1#HY2")
	alpn := asStrings(sub(ob, "tls")["alpn"])
	if !eqStrings(alpn, []string{"h3", "custom-alpn"}) {
		t.Errorf("hy2 alpn = %v, want [h3 custom-alpn]", alpn)
	}
	// sibling: no alpn → nil (runtime injects h3 default), byte-identical.
	ob2 := mustOutbound(t, "hysteria2://pass@example.com:443/?sni=example.com&insecure=1#HY2")
	if a := asStrings(sub(ob2, "tls")["alpn"]); len(a) != 0 {
		t.Errorf("hy2 no-alpn = %v, want empty", a)
	}
}

// #13/#14 — uTLS: dropped for net=quic h3 (no h3 ClientHello); preserved with nosni.
func TestCorpus_UTLS_Guards(t *testing.T) {
	// quic+h3+fp → uTLS must be nil (no HTTP/3 ClientHello support).
	quic := mustOutbound(t, "vless://"+corpusUUID+"@host:443?type=quic&security=tls&fp=chrome&sni=example.com#quic")
	if sub(quic, "tls")["utls"] != nil {
		t.Error("net=quic h3 + fp: utls must be nil (h3 ClientHello unsupported)")
	}
	// sibling: ws+fp → uTLS present.
	ws := mustOutbound(t, "vless://"+corpusUUID+"@host:443?type=ws&security=tls&fp=chrome&sni=example.com&host=example.com&path=/p#ws")
	if u := sub(sub(ws, "tls"), "utls"); u == nil || u["fingerprint"] != "chrome" {
		t.Errorf("ws+fp: utls should be present with chrome, got %v", sub(ws, "tls")["utls"])
	}
	// #14 — nosni=1 + fp must STILL carry uTLS (anti-DPI) and disable_sni.
	nosni := mustOutbound(t, "vless://"+corpusUUID+"@1.2.3.4:443?security=tls&fp=chrome&nosni=1#ipnode")
	tls := sub(nosni, "tls")
	if v, _ := tls["disable_sni"].(bool); !v {
		t.Error("nosni=1: disable_sni should be true")
	}
	if u := sub(tls, "utls"); u == nil || u["fingerprint"] != "chrome" {
		t.Errorf("nosni=1 + fp: utls must be preserved, got %v", tls["utls"])
	}
}

// #1/#4/#5/#6 — mieru/ssh route to the canonical CORE parser (the Dart app no
// longer re-translates them). These assert the core output the app now delegates to.
func TestCorpus_MieruSSH_Core(t *testing.T) {
	mieru := mustOutbound(t, "mieru://baozi:manlianpenfen@1.2.3.4?protocol=TCP&port=6666&multiplexing=MULTIPLEXING_HIGH&handshake-mode=HANDSHAKE_NO_WAIT#node")
	if mieru["server_port"] != float64(0) {
		t.Errorf("mieru server_port = %v, want 0 (portBindings carry the port)", mieru["server_port"])
	}
	pb, _ := mieru["portBindings"].([]any)
	if len(pb) != 1 {
		t.Fatalf("mieru portBindings = %v, want exactly 1 binding", mieru["portBindings"])
	}
	if b0 := pb[0].(map[string]any); b0["protocol"] != "TCP" || b0["port"] != float64(6666) {
		t.Errorf("mieru binding = %v, want {TCP,6666}", b0)
	}
	if mieru["handshake_mode"] != "HANDSHAKE_NO_WAIT" || mieru["multiplexing"] != "MULTIPLEXING_HIGH" {
		t.Errorf("mieru handshake/mux = %v / %v (want HANDSHAKE_NO_WAIT / MULTIPLEXING_HIGH)", mieru["handshake_mode"], mieru["multiplexing"])
	}

	ssh := mustOutbound(t, "ssh://root:password123@1.2.3.4:22#node")
	if ssh["user"] != "root" || ssh["password"] != "password123" {
		t.Errorf("ssh user/pass = %v / %v", ssh["user"], ssh["password"])
	}
	if v, _ := ssh["udp_over_tcp"].(bool); !v {
		t.Error("ssh udp_over_tcp must be true")
	}
	// host_key / host_key_algorithms must be ABSENT when not provided (sing-box rejects ['']).
	if _, ok := ssh["host_key"]; ok {
		t.Error("ssh host_key should be omitted when absent (sing-box rejects [''])")
	}
}

// Cross-path equivalence (root #2 guard): a config expressed as a share-link and
// as Xray JSON must produce the SAME sing-box outbound. json_ingest is by design a
// JSON→URI transcoder feeding the same per-protocol parsers, so any divergence here
// is a transcoder drop — this single test catches the WHOLE class automatically, not
// just the tcp-header / xhttp-extra instances we found by hand.
//
// 2026-07-19 — widened from two paths to FOUR. There are four ways a foreign
// subscription reaches us (share-link, Xray JSON, native sing-box JSON, Clash YAML)
// and three of them are URI transcoders, so a field with no query spelling is lost
// BY CONSTRUCTION on whichever transcoder forgot it. Pinning every container
// dialect against the same share-link is what makes that structural, not a
// per-bug whack-a-mole: an unfilled `singbox`/`clash` column is an untested cell.
func TestCrossPath_ShareLinkVsJSON(t *testing.T) {
	u := corpusUUID
	cases := []struct{ name, link, jsonCfg, singbox, clash string }{
		{
			name:    "vless_ws_tls",
			link:    "vless://" + u + "@cdn.example.com:443?type=ws&security=tls&sni=cdn.example.com&fp=chrome&path=%2Fp&host=cdn.example.com&encryption=none#n",
			jsonCfg: `{"protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"` + u + `","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example.com","fingerprint":"chrome"},"wsSettings":{"path":"/p","headers":{"Host":"cdn.example.com"}}}}`,
			singbox: `{"type":"vless","tag":"n","server":"cdn.example.com","server_port":443,"uuid":"` + u + `","tls":{"enabled":true,"server_name":"cdn.example.com","utls":{"enabled":true,"fingerprint":"chrome"}},"transport":{"type":"ws","path":"/p","headers":{"Host":"cdn.example.com"}}}`,
			clash: "proxies:\n  - name: n\n    type: vless\n    server: cdn.example.com\n    port: 443\n    uuid: " + u + "\n    tls: true\n    servername: cdn.example.com\n    client-fingerprint: chrome\n    network: ws\n    ws-opts:\n      path: /p\n      headers:\n        Host: cdn.example.com\n",
		},
		{
			name:    "trojan_ws_tls",
			link:    "trojan://pass123@cdn.example.com:443?type=ws&security=tls&sni=cdn.example.com&path=%2Ft&host=cdn.example.com#n",
			jsonCfg: `{"protocol":"trojan","settings":{"servers":[{"address":"cdn.example.com","port":443,"password":"pass123"}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example.com"},"wsSettings":{"path":"/t","headers":{"Host":"cdn.example.com"}}}}`,
			singbox: `{"type":"trojan","tag":"n","server":"cdn.example.com","server_port":443,"password":"pass123","tls":{"enabled":true,"server_name":"cdn.example.com"},"transport":{"type":"ws","path":"/t","headers":{"Host":"cdn.example.com"}}}`,
			clash:   "proxies:\n  - name: n\n    type: trojan\n    server: cdn.example.com\n    port: 443\n    password: pass123\n    sni: cdn.example.com\n    network: ws\n    ws-opts:\n      path: /t\n      headers:\n        Host: cdn.example.com\n",
		},
		{
			name:    "vless_grpc_tls",
			link:    "vless://" + u + "@cdn.example.com:443?type=grpc&security=tls&sni=cdn.example.com&fp=chrome&serviceName=gsvc&encryption=none#n",
			jsonCfg: `{"protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"` + u + `","encryption":"none"}]}]},"streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"serverName":"cdn.example.com","fingerprint":"chrome"},"grpcSettings":{"serviceName":"gsvc"}}}`,
			singbox: `{"type":"vless","tag":"n","server":"cdn.example.com","server_port":443,"uuid":"` + u + `","tls":{"enabled":true,"server_name":"cdn.example.com","utls":{"enabled":true,"fingerprint":"chrome"}},"transport":{"type":"grpc","service_name":"gsvc"}}`,
			clash: "proxies:\n  - name: n\n    type: vless\n    server: cdn.example.com\n    port: 443\n    uuid: " + u + "\n    tls: true\n    servername: cdn.example.com\n    client-fingerprint: chrome\n    network: grpc\n    grpc-opts:\n      grpc-service-name: gsvc\n",
		},
		{
			// REALITY + the uTLS fingerprint across every dialect. The Clash and
			// sing-box columns are the ones that used to drop pbk/sid on vmess;
			// vless kept them, which is exactly how the divergence hid.
			name:    "vless_tcp_reality",
			link:    "vless://" + u + "@1.2.3.4:443?type=tcp&security=reality&sni=www.example.org&fp=chrome&pbk=PUBKEY123&sid=ab12&encryption=none#n",
			jsonCfg: `{"protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"` + u + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.org","publicKey":"PUBKEY123","shortId":"ab12","fingerprint":"chrome"}}}`,
			singbox: `{"type":"vless","tag":"n","server":"1.2.3.4","server_port":443,"uuid":"` + u + `","tls":{"enabled":true,"server_name":"www.example.org","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"PUBKEY123","short_id":"ab12"}}}`,
			clash: "proxies:\n  - name: n\n    type: vless\n    server: 1.2.3.4\n    port: 443\n    uuid: " + u + "\n    tls: true\n    servername: www.example.org\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: PUBKEY123\n      short-id: ab12\n",
		},
		{
			// vmess is the protocol where all three transcoders hand-rolled their
			// own smaller mapping. insecure + fp are the fields that went missing.
			name:    "vmess_ws_tls_insecure",
			link:    "vmess://" + vmessLink(map[string]string{"v": "2", "ps": "n", "add": "cdn.example.com", "port": "443", "id": u, "aid": "0", "scy": "auto", "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/p", "tls": "tls", "sni": "cdn.example.com", "fp": "firefox", "insecure": "1"}),
			jsonCfg: `{"protocol":"vmess","tag":"n","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"` + u + `","alterId":0,"security":"auto"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example.com","fingerprint":"firefox","allowInsecure":true},"wsSettings":{"path":"/p","headers":{"Host":"cdn.example.com"}}}}`,
			singbox: `{"type":"vmess","tag":"n","server":"cdn.example.com","server_port":443,"uuid":"` + u + `","alter_id":0,"security":"auto","tls":{"enabled":true,"server_name":"cdn.example.com","insecure":true,"utls":{"enabled":true,"fingerprint":"firefox"}},"transport":{"type":"ws","path":"/p","headers":{"Host":"cdn.example.com"}}}`,
			clash: "proxies:\n  - name: n\n    type: vmess\n    server: cdn.example.com\n    port: 443\n    uuid: " + u + "\n    alterId: 0\n    cipher: auto\n    tls: true\n    servername: cdn.example.com\n    client-fingerprint: firefox\n    skip-cert-verify: true\n    network: ws\n    ws-opts:\n      path: /p\n      headers:\n        Host: cdn.example.com\n",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			want := canonicalOutbound(t, c.link)
			for _, alt := range []struct{ path, cfg string }{
				{"xray-json", c.jsonCfg},
				{"singbox-json", c.singbox},
				{"clash-yaml", c.clash},
			} {
				if alt.cfg == "" {
					continue
				}
				got := canonicalOutbound(t, alt.cfg)
				if got != want {
					t.Errorf("share-link vs %s diverge (transcoder drop):\n--- share-link ---\n%s\n--- %s ---\n%s", alt.path, want, alt.path, got)
				}
			}
		})
	}
}

// canonicalOutbound renders the first outbound as stable JSON with the tag
// stripped (the tag carries a positional " § N" suffix and the container's own
// node name, neither of which is part of the semantic outbound).
func canonicalOutbound(t *testing.T, config string) string {
	t.Helper()
	ob := mustOutbound(t, config)
	delete(ob, "tag")
	b, _ := json.MarshalIndent(ob, "", " ")
	return string(b)
}

// vmessLink builds the base64(JSON) body of a vmess:// share-link.
func vmessLink(m map[string]string) string {
	b, _ := json.Marshal(m)
	return base64.StdEncoding.EncodeToString(b)
}

// reparse feeds an already-produced sing-box outbound back through the pipeline.
//
// This is not a synthetic scenario: the app STORES a parsed node as its sing-box
// outbound JSON and re-parses it on every ping and every connect. So any field
// singbox_ingest cannot round-trip does not merely fail to import — it evaporates
// on the second parse and the node degrades in place, for good, with err == nil
// every time. Idempotency here is the guard for that whole class.
func reparse(t *testing.T, ob map[string]any) map[string]any {
	t.Helper()
	clone := make(map[string]any, len(ob))
	for k, v := range ob {
		clone[k] = v
	}
	b, err := json.Marshal(map[string]any{"outbounds": []any{clone}})
	if err != nil {
		t.Fatalf("re-marshal outbound: %v", err)
	}
	return mustOutbound(t, string(b))
}

// assertReparseStable parses a config, re-parses the result, and requires the two
// outbounds to be identical.
func assertReparseStable(t *testing.T, config string) map[string]any {
	t.Helper()
	first := mustOutbound(t, config)
	second := reparse(t, first)
	delete(first, "tag")
	delete(second, "tag")
	a, _ := json.MarshalIndent(first, "", " ")
	b, _ := json.MarshalIndent(second, "", " ")
	if string(a) != string(b) {
		t.Errorf("outbound is not stable under re-parse (the node degrades on every ping/connect):\n--- first parse ---\n%s\n--- second parse ---\n%s", a, b)
	}
	return first
}

// #9 — JSON-ingest must NOT drop tcp HTTP-header obfuscation.
func TestCorpus_JSON_TCPHeaderObfs(t *testing.T) {
	withHdr := `{"protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"d43ee5e3-1b07-56d7-b2ea-8d22c44fdc66","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tcpSettings":{"header":{"type":"http","request":{"path":["/live"],"headers":{"Host":["front.example.com"]}}}}}}`
	ob := mustOutbound(t, withHdr)
	tr := sub(ob, "transport")
	if tr == nil || tr["type"] != "http" {
		t.Fatalf("tcp+http-header → transport type = %v, want http (promoted)", tr["type"])
	}
	if hosts := asStrings(tr["host"]); !eqStrings(hosts, []string{"front.example.com"}) {
		t.Errorf("host = %v, want [front.example.com]", hosts)
	}
	if tr["path"] != "/live" {
		t.Errorf("path = %v, want /live", tr["path"])
	}
	// sibling: plain TCP (no header) → no transport, byte-identical.
	plain := `{"protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"d43ee5e3-1b07-56d7-b2ea-8d22c44fdc66","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}`
	ob2 := mustOutbound(t, plain)
	if tr := sub(ob2, "transport"); tr != nil {
		t.Errorf("plain TCP should have no transport, got %v", tr)
	}
}

// 2026-07-19 — JSON-ingest must NOT drop xhttpSettings top-level fields.
//
// The JSON path decoded xhttpSettings into exactly four fields (path/host/mode/
// extra) and silently discarded everything else Xray supports (SplitHTTPConfig has
// ~30: xmux, downloadSettings, sc*, headers, noGRPCHeader, uplinkHTTPMethod, the
// whole obfs set). Textbook silent-fail: outbound builds, err == nil, traffic runs
// with the wrong parameters. Fix forwards the whole settings object as `extra`.
//
// xmux is the assertion target because it is the field whose absence measurably
// broke a live CDN backend (unlimited streams onto one never-rotated connection).
func TestCorpus_JSON_XHTTP_TopLevelFields(t *testing.T) {
	u := corpusUUID
	cfg := `{"protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"` + u + `","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"cdn.example.com","alpn":["h2"]},"xhttpSettings":{"path":"/x","host":"cdn.example.com","mode":"packet-up","noGRPCHeader":true,"xmux":{"maxConcurrency":"16-32","hMaxRequestTimes":"600-900"}}}}`
	tr := sub(mustOutbound(t, cfg), "transport")
	if tr == nil || tr["type"] != "xhttp" {
		t.Fatalf("transport = %v, want xhttp", tr)
	}
	xmux, _ := tr["xmux"].(map[string]any)
	if xmux == nil {
		t.Fatal("xmux dropped by the JSON transcoder (top-level xhttpSettings fields lost)")
	}
	if got := xmux["maxConcurrency"]; got != "16-32" {
		t.Errorf("xmux.maxConcurrency = %v, want 16-32", got)
	}
	if tr["noGRPCHeader"] != true {
		t.Errorf("noGRPCHeader = %v, want true (top-level field must survive)", tr["noGRPCHeader"])
	}
	// sibling: an explicit `extra` still wins wholesale (Xray SplitHTTPConfig.Build
	// does `c = &extra`), so a top-level xmux next to it must NOT leak through.
	withExtra := `{"protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"` + u + `","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"cdn.example.com","alpn":["h2"]},"xhttpSettings":{"path":"/x","host":"cdn.example.com","mode":"packet-up","xmux":{"maxConcurrency":"16-32"},"extra":{"noGRPCHeader":true}}}}`
	tr2 := sub(mustOutbound(t, withExtra), "transport")
	if _, leaked := tr2["xmux"]; leaked {
		t.Errorf("explicit `extra` must replace the whole config; top-level xmux leaked: %v", tr2["xmux"])
	}
}

// 2026-07-19 — top-level host/path must beat the `extra` blob.
//
// Xray (infra/conf/transport_method.go SplitHTTPConfig.Build) unpacks `extra` into
// the full config and then force-assigns host/path/mode from the top level. Ours
// only filled them when `extra` left them empty, so `extra` silently overrode an
// explicitly requested Host — on a CDN-fronted node that quietly retargets the
// request to a different backend with no error anywhere.
func TestCorpus_XHTTP_TopLevelHostBeatsExtra(t *testing.T) {
	u := corpusUUID
	link := "vless://" + u + "@1.2.3.4:443?type=xhttp&security=tls&sni=cdn.example.com&encryption=none" +
		"&host=front.example.com&path=%2Fwanted" +
		"&extra=" + urlQueryEscape(`{"host":"stale.example.com","path":"/stale","noGRPCHeader":true}`) + "#n"
	tr := sub(mustOutbound(t, link), "transport")
	if tr == nil || tr["type"] != "xhttp" {
		t.Fatalf("transport = %v, want xhttp", tr)
	}
	if tr["host"] != "front.example.com" {
		t.Errorf("host = %v, want front.example.com (top-level must win over extra)", tr["host"])
	}
	if tr["path"] != "/wanted" {
		t.Errorf("path = %v, want /wanted (top-level must win over extra)", tr["path"])
	}
	// sibling: fields that only `extra` carries still come through.
	if tr["noGRPCHeader"] != true {
		t.Errorf("noGRPCHeader = %v, want true (extra must still supply non-host/path fields)", tr["noGRPCHeader"])
	}
	// sibling: when the link omits host/path, extra's values must NOT be wiped.
	// (Deliberate deviation from Xray, which force-assigns even an empty top level —
	// see the rationale comment in ray2sing/common.go.)
	linkNoHost := "vless://" + u + "@1.2.3.4:443?type=xhttp&security=tls&sni=cdn.example.com&encryption=none" +
		"&extra=" + urlQueryEscape(`{"host":"kept.example.com","path":"/kept"}`) + "#n"
	tr3 := sub(mustOutbound(t, linkNoHost), "transport")
	if tr3["host"] != "kept.example.com" {
		t.Errorf("host = %v, want kept.example.com (empty top level must not wipe extra)", tr3["host"])
	}
}

// 2026-07-19 — a NATIVE sing-box outbound must not lose its xhttp transport.
//
// singbox_ingest's transport applier handled ws/grpc/http only, so `type: xhttp`
// emitted nothing but type=xhttp: host and path collapsed to empty, mode fell back
// to "auto", and xmux / downloadSettings / noGRPCHeader / the whole obfs set were
// gone. Worst of the JSON drops because the app re-parses the STORED outbound on
// every ping and connect, so an xhttp node degraded on each cycle rather than only
// at import — always with err == nil.
func TestCorpus_SingboxJSON_XHTTP_Transport(t *testing.T) {
	cfg := `{"outbounds":[{"type":"vless","tag":"n","server":"1.2.3.4","server_port":443,"uuid":"` + corpusUUID + `",` +
		`"tls":{"enabled":true,"server_name":"cdn.example.com","alpn":["h2"]},` +
		`"transport":{"type":"xhttp","mode":"packet-up","host":"front.example.com","path":"/x","noGRPCHeader":true,` +
		`"xmux":{"maxConcurrency":"16-32"},` +
		`"downloadSettings":{"server":"dl.example.com","server_port":8443,"path":"/d","tls":{"enabled":true,"server_name":"dl.example.com"}}}}]}`

	tr := sub(assertReparseStable(t, cfg), "transport")
	if tr == nil || tr["type"] != "xhttp" {
		t.Fatalf("transport = %v, want xhttp", tr)
	}
	if tr["mode"] != "packet-up" {
		t.Errorf("mode = %v, want packet-up (was silently reset to auto)", tr["mode"])
	}
	if tr["host"] != "front.example.com" {
		t.Errorf("host = %v, want front.example.com", tr["host"])
	}
	if tr["path"] != "/x" {
		t.Errorf("path = %v, want /x", tr["path"])
	}
	if tr["noGRPCHeader"] != true {
		t.Errorf("noGRPCHeader = %v, want true", tr["noGRPCHeader"])
	}
	xmux, _ := tr["xmux"].(map[string]any)
	if xmux == nil || xmux["maxConcurrency"] != "16-32" {
		t.Errorf("xmux = %v, want maxConcurrency 16-32 (unbounded streams on one connection when lost)", tr["xmux"])
	}
	// The download leg travels in sing-box's own dialect (server/server_port/tls)
	// inside downloadSettings — it must be folded onto the Xray spelling, not
	// dropped, or the downlink dials an empty address.
	dl := sub(tr, "downloadSettings")
	if dl == nil || dl["server"] != "dl.example.com" || dl["server_port"] != float64(8443) {
		t.Errorf("downloadSettings = %v, want server dl.example.com:8443", tr["downloadSettings"])
	}
	if dtls := sub(dl, "tls"); dtls == nil || dtls["server_name"] != "dl.example.com" {
		t.Errorf("downloadSettings.tls = %v, want server_name dl.example.com", dl["tls"])
	}
}

// 2026-07-19 — httpupgrade `host` is a TOP-LEVEL sing-box field, not a header.
// Reading only Headers["Host"] silently stripped the Host from every CDN-fronted
// httpupgrade node, which then hit the origin's default vhost.
func TestCorpus_SingboxJSON_HTTPUpgradeHost(t *testing.T) {
	cfg := `{"outbounds":[{"type":"vless","tag":"n","server":"1.2.3.4","server_port":443,"uuid":"` + corpusUUID + `",` +
		`"tls":{"enabled":true,"server_name":"a.example.com"},` +
		`"transport":{"type":"httpupgrade","host":"front.example.com","path":"/hu"}}]}`
	tr := sub(assertReparseStable(t, cfg), "transport")
	if tr == nil || tr["type"] != "httpupgrade" {
		t.Fatalf("transport = %v, want httpupgrade", tr)
	}
	hdrs := sub(tr, "headers")
	if hdrs == nil || !eqStrings(asStrings(hdrs["Host"]), []string{"front.example.com"}) {
		t.Errorf("httpupgrade Host = %v, want front.example.com (top-level host was ignored)", tr["headers"])
	}
	// A multi-value header map must not blow up the unmarshal: sing-box marshals
	// HTTPHeader values as arrays, and a map[string]string model made the WHOLE
	// outbound fail to decode, i.e. the node vanished from the list.
	arrayHdrs := `{"outbounds":[{"type":"vless","tag":"n","server":"1.2.3.4","server_port":443,"uuid":"` + corpusUUID + `",` +
		`"tls":{"enabled":true,"server_name":"a.example.com"},` +
		`"transport":{"type":"ws","path":"/p","headers":{"Host":["front.example.com"],"X-Tag":["a","b"]}}}]}`
	if n := outboundCount(t, arrayHdrs); n != 1 {
		t.Errorf("array-valued headers: built %d outbound(s), want 1 (whole node was dropped on unmarshal)", n)
	}
}

// 2026-07-19 — ECH must survive every JSON/YAML ingest path.
//
// PRIVACY class, not convenience: none of the three container paths read ECH, so a
// node configured for Encrypted Client Hello came out without it and sent its SNI
// in PLAINTEXT. Nothing errors, the node still connects — the user just silently
// loses the one property they enabled ECH for.
func TestCorpus_ECH_AllContainerPaths(t *testing.T) {
	const blob = "AEX+DQBBhwAgACCbLNiZ" // opaque ECHConfigList payload
	cases := []struct{ name, cfg string }{
		{
			"xray_json",
			`{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"` + corpusUUID + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com","echConfigList":"` + blob + `"}}}`,
		},
		{
			"singbox_json",
			`{"outbounds":[{"type":"vless","tag":"n","server":"a.example.com","server_port":443,"uuid":"` + corpusUUID + `","tls":{"enabled":true,"server_name":"a.example.com","ech":{"enabled":true,"config":["-----BEGIN ECH CONFIGS-----\n` + blob + `\n-----END ECH CONFIGS-----"]}}}]}`,
		},
		{
			"clash_yaml",
			"proxies:\n  - name: n\n    type: vless\n    server: a.example.com\n    port: 443\n    uuid: " + corpusUUID + "\n    tls: true\n    servername: a.example.com\n    ech-opts:\n      enable: true\n      config: " + blob + "\n",
		},
		{
			"xray_json_vmess",
			`{"protocol":"vmess","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"` + corpusUUID + `","alterId":0}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com","echConfigList":"` + blob + `"}}}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ech := sub(sub(mustOutbound(t, c.cfg), "tls"), "ech")
			if ech == nil {
				t.Fatal("tls.ech missing — the SNI goes out in plaintext")
			}
			if v, _ := ech["enabled"].(bool); !v {
				t.Errorf("tls.ech.enabled = %v, want true", ech["enabled"])
			}
			cfgList := strings.Join(asStrings(ech["config"]), "\n")
			if !strings.Contains(cfgList, blob) {
				t.Errorf("tls.ech.config = %q, want it to carry the ECHConfigList blob", cfgList)
			}
		})
	}
	// sibling: no ECH anywhere => the key stays absent (byte-identical).
	plain := `{"protocol":"vless","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"` + corpusUUID + `","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com"}}}`
	if e := sub(mustOutbound(t, plain), "tls")["ech"]; e != nil {
		t.Errorf("no-ECH node grew an ech block: %v", e)
	}
}

// 2026-07-19 — Clash `network: h2` / `network: http` must keep host+path.
//
// h2-opts / http-opts were not modelled at all, so the transport was built with
// path "/" and no Host: on a CDN-fronted node that is a 404 on every request,
// with nothing logged client-side.
func TestCorpus_Clash_H2_And_HTTPOpts(t *testing.T) {
	h2 := "proxies:\n  - name: n\n    type: vless\n    server: 1.2.3.4\n    port: 443\n    uuid: " + corpusUUID +
		"\n    tls: true\n    servername: a.example.com\n    network: h2\n    h2-opts:\n      host:\n        - one.example.com\n        - two.example.com\n      path: /h2\n"
	tr := sub(mustOutbound(t, h2), "transport")
	if tr == nil || tr["type"] != "http" {
		t.Fatalf("h2 transport = %v, want http (h2 folds onto the http transport)", tr)
	}
	if !eqStrings(asStrings(tr["host"]), []string{"one.example.com", "two.example.com"}) {
		t.Errorf("h2 host = %v, want the full rotation list", tr["host"])
	}
	if tr["path"] != "/h2" {
		t.Errorf("h2 path = %v, want /h2 (was falling back to \"/\")", tr["path"])
	}

	// network: http is mihomo's TCP + HTTP/1.1 header obfuscation.
	obfs := "proxies:\n  - name: n\n    type: vmess\n    server: 1.2.3.4\n    port: 443\n    uuid: " + corpusUUID +
		"\n    alterId: 0\n    cipher: auto\n    network: http\n    http-opts:\n      method: GET\n      path:\n        - /live\n      headers:\n        Host:\n          - front.example.com\n"
	tr2 := sub(mustOutbound(t, obfs), "transport")
	if tr2 == nil || tr2["type"] != "http" {
		t.Fatalf("http-obfs transport = %v, want http (promoted from tcp+headerType)", tr2)
	}
	if !eqStrings(asStrings(tr2["host"]), []string{"front.example.com"}) {
		t.Errorf("http-obfs host = %v, want front.example.com", tr2["host"])
	}
	if tr2["path"] != "/live" {
		t.Errorf("http-obfs path = %v, want /live", tr2["path"])
	}
}

// 2026-07-19 — Clash Shadowsocks must keep its SIP003 plugin.
//
// plugin / plugin-opts were dropped, so an obfs-wrapped node was rebuilt as BARE
// shadowsocks: it parses, it builds, and then the server rejects every packet.
func TestCorpus_Clash_SS_Plugin(t *testing.T) {
	y := "proxies:\n  - name: n\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n" +
		"    plugin: obfs\n    plugin-opts:\n      mode: http\n      host: bing.com\n"
	ob := mustOutbound(t, y)
	if ob["plugin"] != "obfs-local" {
		t.Errorf("plugin = %v, want obfs-local (SIP002 spelling of simple-obfs)", ob["plugin"])
	}
	opts, _ := ob["plugin_opts"].(string)
	if !strings.Contains(opts, "mode=http") || !strings.Contains(opts, "host=bing.com") {
		t.Errorf("plugin_opts = %q, want mode=http and host=bing.com", opts)
	}
	// sibling: a plain SS node must stay plugin-free (byte-identical).
	plain := "proxies:\n  - name: n\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n"
	if p := mustOutbound(t, plain)["plugin"]; p != nil && p != "" {
		t.Errorf("plain SS grew a plugin: %v", p)
	}
}

// 2026-07-19 — vmess TLS fields must survive EVERY container branch.
//
// All three transcoders hand-rolled a smaller mapping for vmess than for
// vless/trojan, so insecure / fingerprint / reality were lost on vmess only —
// which is precisely why it stayed hidden. Damage per field:
//   - reality dropped  => plain-TLS handshake against a REALITY server, node dead;
//   - fp dropped       => vmess.go substitutes chrome, silently replacing the
//     ClientHello signature the operator picked for DPI evasion;
//   - insecure dropped => verification ends up STRICTER than configured, so a
//     self-signed node fails closed (a dead node, not a weakened one) — worth
//     stating explicitly, because the reverse direction would be a real hole.
func TestCorpus_VMess_TLSFields_AllContainers(t *testing.T) {
	u := corpusUUID
	t.Run("insecure_and_fp", func(t *testing.T) {
		cases := map[string]string{
			"xray_json":    `{"protocol":"vmess","settings":{"vnext":[{"address":"a.example.com","port":443,"users":[{"id":"` + u + `","alterId":0}]}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"a.example.com","fingerprint":"firefox","allowInsecure":true}}}`,
			"singbox_json": `{"outbounds":[{"type":"vmess","tag":"n","server":"a.example.com","server_port":443,"uuid":"` + u + `","alter_id":0,"tls":{"enabled":true,"server_name":"a.example.com","insecure":true,"utls":{"enabled":true,"fingerprint":"firefox"}}}]}`,
			"clash_yaml":   "proxies:\n  - name: n\n    type: vmess\n    server: a.example.com\n    port: 443\n    uuid: " + u + "\n    alterId: 0\n    cipher: auto\n    tls: true\n    servername: a.example.com\n    skip-cert-verify: true\n    client-fingerprint: firefox\n",
		}
		for name, cfg := range cases {
			t.Run(name, func(t *testing.T) {
				tls := sub(mustOutbound(t, cfg), "tls")
				if v, _ := tls["insecure"].(bool); !v {
					t.Error("tls.insecure = false; allowInsecure/skip-cert-verify was dropped (node fails cert verification it was told to skip)")
				}
				if fp := sub(tls, "utls"); fp == nil || fp["fingerprint"] != "firefox" {
					t.Errorf("utls = %v, want firefox (dropped fp silently degrades to the chrome default)", tls["utls"])
				}
			})
		}
	})
	t.Run("reality", func(t *testing.T) {
		cases := map[string]string{
			"singbox_json": `{"outbounds":[{"type":"vmess","tag":"n","server":"1.2.3.4","server_port":443,"uuid":"` + u + `","alter_id":0,"tls":{"enabled":true,"server_name":"www.example.org","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"PUBKEY123","short_id":"ab12"}}}]}`,
			"clash_yaml":   "proxies:\n  - name: n\n    type: vmess\n    server: 1.2.3.4\n    port: 443\n    uuid: " + u + "\n    alterId: 0\n    cipher: auto\n    tls: true\n    servername: www.example.org\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: PUBKEY123\n      short-id: ab12\n",
		}
		for name, cfg := range cases {
			t.Run(name, func(t *testing.T) {
				r := sub(sub(mustOutbound(t, cfg), "tls"), "reality")
				if r == nil {
					t.Fatal("tls.reality missing — a REALITY node was rebuilt as plain TLS (handshake fails)")
				}
				if r["public_key"] != "PUBKEY123" || r["short_id"] != "ab12" {
					t.Errorf("reality = %v, want PUBKEY123/ab12", r)
				}
			})
		}
	})
	t.Run("xray_json_vmess_xhttp_extra", func(t *testing.T) {
		// The vmess branch of the Xray path never forwarded mode or the top-level
		// xhttpSettings object, so vmess+xhttp lost xmux and friends long after the
		// vless branch was fixed.
		cfg := `{"protocol":"vmess","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"` + u + `","alterId":0}]}]},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"serverName":"cdn.example.com"},"xhttpSettings":{"path":"/x","host":"cdn.example.com","mode":"stream-up","noGRPCHeader":true,"xmux":{"maxConcurrency":"16-32"}}}}`
		tr := sub(mustOutbound(t, cfg), "transport")
		if tr == nil || tr["type"] != "xhttp" {
			t.Fatalf("transport = %v, want xhttp", tr)
		}
		if tr["mode"] != "stream-up" {
			t.Errorf("mode = %v, want stream-up", tr["mode"])
		}
		xmux, _ := tr["xmux"].(map[string]any)
		if xmux == nil || xmux["maxConcurrency"] != "16-32" {
			t.Errorf("xmux = %v, want maxConcurrency 16-32", tr["xmux"])
		}
	})
}

// #1 (JSON path) — the per-transport ALPN clamp must fire on the JSON-ingest path
// too, not just on share-links. alpn_transport_test.go locks the share-link path;
// this locks JSON. The clamp lives in the per-protocol parser (common.go), but it
// only fires if the JSON→URI transcoder preserves BOTH the network AND the alpn:
// drop either and a ws+tls node silently re-offers h2 → EOF (the original 2026-06-26
// bug). This test catches that transcoder drop, which the share-link test cannot.
func TestCorpus_JSON_WS_ALPN_Clamp(t *testing.T) {
	u := corpusUUID
	// ws + TLS + alpn=["http/1.1","h2"] → h2 dropped, clamped to http/1.1.
	ws := `{"protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"` + u + `","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example.com","alpn":["http/1.1","h2"]},"wsSettings":{"path":"/p","headers":{"Host":"cdn.example.com"}}}}`
	if alpn := asStrings(sub(mustOutbound(t, ws), "tls")["alpn"]); !eqStrings(alpn, []string{"http/1.1"}) {
		t.Errorf("ws+tls JSON alpn = %v, want [http/1.1] (h2 must be clamped on the JSON path too)", alpn)
	}
	// sibling: gRPC over the same alpn → clamped to h2 (HTTP/2 transport).
	grpc := `{"protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"` + u + `","encryption":"none"}]}]},"streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"serverName":"cdn.example.com","alpn":["http/1.1","h2"]},"grpcSettings":{"serviceName":"gsvc"}}}`
	if alpn := asStrings(sub(mustOutbound(t, grpc), "tls")["alpn"]); !eqStrings(alpn, []string{"h2"}) {
		t.Errorf("grpc+tls JSON alpn = %v, want [h2]", alpn)
	}
}
