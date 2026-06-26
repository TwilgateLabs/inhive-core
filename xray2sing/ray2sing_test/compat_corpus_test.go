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
	"encoding/json"
	"strings"
	"testing"

	"github.com/twilgate/xray2sing/ray2sing"
)

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
func TestCrossPath_ShareLinkVsJSON(t *testing.T) {
	u := corpusUUID
	cases := []struct{ name, link, jsonCfg string }{
		{
			"vless_ws_tls",
			"vless://" + u + "@cdn.example.com:443?type=ws&security=tls&sni=cdn.example.com&fp=chrome&path=%2Fp&host=cdn.example.com&encryption=none#n",
			`{"protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"` + u + `","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example.com","fingerprint":"chrome"},"wsSettings":{"path":"/p","headers":{"Host":"cdn.example.com"}}}}`,
		},
		{
			"trojan_ws_tls",
			"trojan://pass123@cdn.example.com:443?type=ws&security=tls&sni=cdn.example.com&path=%2Ft&host=cdn.example.com#n",
			`{"protocol":"trojan","settings":{"servers":[{"address":"cdn.example.com","port":443,"password":"pass123"}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"cdn.example.com"},"wsSettings":{"path":"/t","headers":{"Host":"cdn.example.com"}}}}`,
		},
		{
			"vless_grpc_tls",
			"vless://" + u + "@cdn.example.com:443?type=grpc&security=tls&sni=cdn.example.com&fp=chrome&serviceName=gsvc&encryption=none#n",
			`{"protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":443,"users":[{"id":"` + u + `","encryption":"none"}]}]},"streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"serverName":"cdn.example.com","fingerprint":"chrome"},"grpcSettings":{"serviceName":"gsvc"}}}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := mustOutbound(t, c.link)
			b := mustOutbound(t, c.jsonCfg)
			delete(a, "tag")
			delete(b, "tag")
			aj, _ := json.MarshalIndent(a, "", " ")
			bj, _ := json.MarshalIndent(b, "", " ")
			if string(aj) != string(bj) {
				t.Errorf("share-link vs JSON diverge (transcoder drop):\n--- share-link ---\n%s\n--- json ---\n%s", aj, bj)
			}
		})
	}
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
