package ray2sing

import (
	"context"
	"testing"
)

// TestSingboxNativeJSONIngest verifies that a native sing-box config (outbounds
// keyed by "type", flat fields, nested tls{}/transport{}) — the format UA-gated
// providers serve to sing-box clients — is ingested: every real proxy node is
// rebuilt to a share-link and parsed, while group/system outbounds
// (selector/direct) are filtered out, not turned into fake nodes.
func TestSingboxNativeJSONIngest(t *testing.T) {
	const u = "11111111-2222-3333-4444-555555555555"
	cfg := `{
      "log": {"level":"info"}, "dns": {"servers":[]}, "route": {"rules":[]},
      "outbounds": [
        {"type":"selector","tag":"select","outbounds":["a","b"]},
        {"type":"hysteria2","tag":"hy2node","server":"hy.example.com","server_port":8443,"password":"PW","tls":{"enabled":true,"server_name":"hy.example.com","alpn":["h3"]}},
        {"type":"vless","tag":"vlessnode","server":"v.example.com","server_port":443,"uuid":"` + u + `","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"v.example.com","reality":{"enabled":true,"public_key":"PUBKEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","short_id":"ab12"},"utls":{"enabled":true,"fingerprint":"chrome"}}},
        {"type":"trojan","tag":"trojannode","server":"t.example.com","server_port":443,"password":"TPW","tls":{"enabled":true,"server_name":"t.example.com"},"transport":{"type":"ws","path":"/tj","headers":{"Host":"t.example.com"}}},
        {"type":"shadowsocks","tag":"ssnode","server":"s.example.com","server_port":8388,"method":"aes-256-gcm","password":"SSPW"},
        {"type":"tuic","tag":"tuicnode","server":"tu.example.com","server_port":443,"uuid":"` + u + `","password":"TUPW","congestion_control":"bbr","udp_relay_mode":"native","tls":{"enabled":true,"server_name":"tu.example.com","alpn":["h3"]}},
        {"type":"vmess","tag":"vmessnode","server":"vm.example.com","server_port":443,"uuid":"` + u + `","alter_id":0,"security":"auto","transport":{"type":"ws","path":"/vm","headers":{"Host":"vm.example.com"}},"tls":{"enabled":true,"server_name":"vm.example.com"}},
        {"type":"direct","tag":"direct"}
      ]
    }`

	opts, err := Ray2SingboxOptions(context.Background(), cfg, false)
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}
	got := map[string]int{}
	for _, ob := range opts.Outbounds {
		got[ob.Type]++
	}
	for _, want := range []string{"hysteria2", "vless", "trojan", "shadowsocks", "tuic", "vmess"} {
		if got[want] != 1 {
			t.Errorf("expected exactly 1 %q outbound, got %d (all: %v)", want, got[want], got)
		}
	}
	if got["selector"] != 0 || got["direct"] != 0 {
		t.Errorf("group/system outbounds leaked as nodes: %v", got)
	}
	if len(opts.Outbounds) != 6 {
		t.Errorf("expected 6 proxy outbounds, got %d: %v", len(opts.Outbounds), got)
	}
}
