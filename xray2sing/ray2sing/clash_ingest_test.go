package ray2sing

import (
	"context"
	"strings"
	"testing"
)

// TestClashYAMLIngest verifies that a Clash / Clash.Meta YAML subscription
// (`proxies:` list, clash-specific field names) is ingested: every proxy is
// rebuilt to a share-link and parsed, and non-proxy sections (proxy-groups,
// rules) are ignored.
func TestClashYAMLIngest(t *testing.T) {
	const u = "11111111-2222-3333-4444-555555555555"
	cfg := strings.Join([]string{
		`port: 7890`,
		`mode: rule`,
		`proxies:`,
		`  - {name: "hy2 DE", type: hysteria2, server: hy.example.com, port: 8443, password: PW, sni: hy.example.com, alpn: [h3], skip-cert-verify: false}`,
		`  - name: "vless reality"`,
		`    type: vless`,
		`    server: v.example.com`,
		`    port: 443`,
		`    uuid: ` + u,
		`    flow: xtls-rprx-vision`,
		`    tls: true`,
		`    servername: v.example.com`,
		`    client-fingerprint: chrome`,
		`    reality-opts: {public-key: PUBKEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx, short-id: ab12}`,
		`  - name: "trojan ws"`,
		`    type: trojan`,
		`    server: t.example.com`,
		`    port: 443`,
		`    password: TPW`,
		`    sni: t.example.com`,
		`    network: ws`,
		`    ws-opts: {path: /tj, headers: {Host: t.example.com}}`,
		`  - {name: "ss node", type: ss, server: s.example.com, port: 8388, cipher: aes-256-gcm, password: SSPW}`,
		`  - {name: "tuic node", type: tuic, server: tu.example.com, port: 443, uuid: ` + u + `, password: TUPW, congestion-controller: bbr, udp-relay-mode: native, alpn: [h3], sni: tu.example.com}`,
		`  - name: "vmess ws"`,
		`    type: vmess`,
		`    server: vm.example.com`,
		`    port: 443`,
		`    uuid: ` + u,
		`    alterId: 0`,
		`    cipher: auto`,
		`    network: ws`,
		`    tls: true`,
		`    servername: vm.example.com`,
		`    ws-opts: {path: /vm, headers: {Host: vm.example.com}}`,
		`proxy-groups:`,
		`  - {name: PROXY, type: select, proxies: [DIRECT]}`,
	}, "\n")

	opts, err := Ray2SingboxOptions(context.Background(), cfg, false)
	if err != nil {
		t.Fatalf("clash ingest failed: %v", err)
	}
	got := map[string]int{}
	for _, ob := range opts.Outbounds {
		got[ob.Type]++
	}
	for _, w := range []string{"hysteria2", "vless", "trojan", "shadowsocks", "tuic", "vmess"} {
		if got[w] != 1 {
			t.Errorf("expected exactly 1 %q outbound, got %d (all: %v)", w, got[w], got)
		}
	}
	if len(opts.Outbounds) != 6 {
		t.Errorf("expected 6 proxy outbounds, got %d: %v", len(opts.Outbounds), got)
	}
}
