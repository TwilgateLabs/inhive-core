package ray2sing_test

// zz_sweep_quic_test.go — real-world URI-shape sweep for the QUIC/proxy family:
// hysteria (v1), hysteria2, tuic, socks, http(s), naive, mieru, anytls, dnstt.
//
// Mission class: "real generators emit it, we reject or mangle it". Every
// failing test below is a CONFIRMED finding (left failing on purpose — do not
// "fix" the test; fix the parser). Passing tests are guards documenting shapes
// that already work, so a future fix can't regress them.
//
// Ground truth used for expectations:
//   - hysteria2 official URI spec (v2.x): multi-port hopping syntax in the
//     authority is "host:port1,port2,rangeA-rangeB" (comma list, dash ranges);
//   - sing-quic hysteria.ParsePorts (v0.6.1 client.go:132): every server_ports
//     entry MUST contain ':' and both sides must be uint16 — a bare "8443" or a
//     comma inside one entry kills the node at outbound creation ("bad port
//     range"), which our fork degrades to a SILENT dead node (InvalidConfig);
//   - sing-box protocol/tuic/outbound.go:55 uuid.FromString — a non-UUID token
//     (tuic v4 links) dies at creation, silently;
//   - v2rayN/NekoBox socks export: userinfo is base64("user:pass").

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/twilgate/xray2sing/ray2sing"
)

// qsParse runs one share-link through the full pipeline; returns outbounds and error.
func qsParse(t *testing.T, link string) ([]option.Outbound, error) {
	t.Helper()
	opts, err := ray2sing.Ray2SingboxOptions(context.Background(), link, false)
	if err != nil {
		return nil, err
	}
	return opts.Outbounds, nil
}

// qsOne asserts exactly one outbound came out and returns it.
func qsOne(t *testing.T, link string) *option.Outbound {
	t.Helper()
	outs, err := qsParse(t, link)
	if err != nil {
		t.Fatalf("conversion failed for %s: %v", link, err)
	}
	if len(outs) != 1 {
		t.Fatalf("expected 1 outbound for %s, got %d", link, len(outs))
	}
	return &outs[0]
}

func qsHy2(t *testing.T, link string) *option.Hysteria2OutboundOptions {
	t.Helper()
	o := qsOne(t, link)
	ho, ok := o.Options.(*option.Hysteria2OutboundOptions)
	if !ok {
		t.Fatalf("not hysteria2 options: %T", o.Options)
	}
	return ho
}

// validServerPortsEntry mirrors sing-quic hysteria.ParsePorts acceptance:
// "start:end", both uint16 decimals, nothing else (commas are NOT split there).
var validServerPortsEntry = regexp.MustCompile(`^\d{1,5}:\d{1,5}$`)

func qsAssertServerPortsAlive(t *testing.T, ports []string, link string) {
	t.Helper()
	if len(ports) == 0 {
		t.Fatalf("server_ports empty (hop info lost) for %s", link)
	}
	for _, p := range ports {
		if !validServerPortsEntry.MatchString(p) {
			t.Errorf("server_ports entry %q will fail sing-quic ParsePorts (\"bad port range\") -> SILENT dead node; link: %s", p, link)
		}
	}
}

// ---------------------------------------------------------------------------
// hysteria2 — official multi-port hopping syntax in the authority
// (https://v2.hysteria.network: "addr:80,443,8080-8090"). Go's url.Parse
// rejects the comma port, extractHostPortRange only lifts a single "A-B", so
// the whole node errors out of the subscription ("No outbounds found" when
// it's the only node). Official-spec links are LOST.
// ---------------------------------------------------------------------------

func TestSweepQuic_Hy2AuthorityCommaPorts(t *testing.T) {
	outs, err := qsParse(t, "hysteria2://letmein@example.com:443,8443/?sni=real.example.com#hop-comma")
	if err != nil || len(outs) != 1 {
		t.Fatalf("official hy2 comma multi-port authority rejected (outs=%d err=%v)", len(outs), err)
	}
	ho := outs[0].Options.(*option.Hysteria2OutboundOptions)
	qsAssertServerPortsAlive(t, ho.ServerPorts, "comma authority")
}

func TestSweepQuic_Hy2AuthorityMixedRangeCommaPorts(t *testing.T) {
	outs, err := qsParse(t, "hysteria2://letmein@example.com:500-1000,2000/?sni=real.example.com#hop-mixed")
	if err != nil || len(outs) != 1 {
		t.Fatalf("official hy2 mixed range+comma authority rejected (outs=%d err=%v)", len(outs), err)
	}
	ho := outs[0].Options.(*option.Hysteria2OutboundOptions)
	qsAssertServerPortsAlive(t, ho.ServerPorts, "mixed authority")
}

// Guard: the single-range authority form we DO support must keep working.
func TestSweepQuic_Hy2AuthoritySingleRangeGuard(t *testing.T) {
	ho := qsHy2(t, "hysteria2://letmein@example.com:20000-50000/?sni=real.example.com#hop")
	qsAssertServerPortsAlive(t, ho.ServerPorts, "single range authority")
	if ho.ServerPort != 20000 {
		t.Errorf("dial port should be the low end of the range, got %d", ho.ServerPort)
	}
}

// ---------------------------------------------------------------------------
// hysteria2 / hysteria v1 — mport= query variants.
// strings.ReplaceAll(mp, "-", ":") produces ONE ServerPorts entry; a comma
// list stays glued ("443:8443,9000") and a single port has no ':' ("8443").
// Both fail sing-quic ParsePorts at creation -> silent dead node.
// ---------------------------------------------------------------------------

func TestSweepQuic_Hy2MportCommaList(t *testing.T) {
	ho := qsHy2(t, "hysteria2://pw@example.com:443?sni=x.example.com&mport=443-8443,9000#mport-list")
	qsAssertServerPortsAlive(t, ho.ServerPorts, "mport comma list")
}

func TestSweepQuic_Hy2MportSinglePort(t *testing.T) {
	ho := qsHy2(t, "hysteria2://pw@example.com:443?sni=x.example.com&mport=8443#mport-single")
	qsAssertServerPortsAlive(t, ho.ServerPorts, "mport single port")
}

func TestSweepQuic_Hy1MportSinglePort(t *testing.T) {
	o := qsOne(t, "hysteria://example.com:443?auth=pw&upmbps=10&downmbps=50&mport=8443#v1-mport")
	ho := o.Options.(*option.HysteriaOutboundOptions)
	qsAssertServerPortsAlive(t, ho.ServerPorts, "hysteria v1 mport single port")
}

// ---------------------------------------------------------------------------
// insecure=true — hysteria2.go:89 / hysteria.go:25 / tuic.go:98 compare == "1"
// only. toBool exists and is used for the same flag in http.go. A generator
// emitting the word form gets silent cert verification against a self-signed
// server -> dead node with no reason.
// ---------------------------------------------------------------------------

func TestSweepQuic_Hy2InsecureTrue(t *testing.T) {
	ho := qsHy2(t, "hysteria2://pw@example.com:443?sni=x.example.com&insecure=true#ins")
	if ho.TLS == nil || !ho.TLS.Insecure {
		t.Errorf("hysteria2 insecure=true silently dropped (only \"1\" accepted)")
	}
}

func TestSweepQuic_Hy1InsecureTrue(t *testing.T) {
	o := qsOne(t, "hysteria://example.com:443?auth=pw&upmbps=10&downmbps=50&insecure=true#ins1")
	ho := o.Options.(*option.HysteriaOutboundOptions)
	if ho.TLS == nil || !ho.TLS.Insecure {
		t.Errorf("hysteria v1 insecure=true silently dropped (only \"1\" accepted)")
	}
}

func TestSweepQuic_TuicAllowInsecureTrue(t *testing.T) {
	o := qsOne(t, "tuic://00000000-0000-0000-0000-000000000001:pass@example.com:443?congestion_control=bbr&allow_insecure=true#tins")
	to := o.Options.(*option.TUICOutboundOptions)
	if to.TLS == nil || !to.TLS.Insecure {
		t.Errorf("tuic allow_insecure=true silently dropped (only \"1\" accepted)")
	}
}

// ---------------------------------------------------------------------------
// hysteria2 pinSHA256= — official URI param carrying the trust anchor for a
// self-signed deployment. Dropped silently; without insecure=1 the node then
// fails system-CA verification at runtime. (Note: hy2 pins the cert SHA-256,
// sing-box exposes certificate_public_key_sha256 — mapping needs care; the
// finding is the SILENT drop of the user's declared trust anchor.)
// ---------------------------------------------------------------------------

// Решение (2026-09-02): sing-box НЕ несёт cert-hash пиннинга (его
// certificate_public_key_sha256 — хеш ПУБЛИЧНОГО КЛЮЧА, семантика другая:
// маппинг «не совпадёт никогда» = мёртвая нода без объяснения). Тихий дроп
// пина — либо ложная безопасность, либо криптичная смерть на verify.
// Каноничный исход: ЧИТАЕМАЯ ошибка конверсии, называющая параметр.
func TestSweepQuic_Hy2PinSHA256NotDropped(t *testing.T) {
	link := "hysteria2://pw@example.com:443?sni=x.example.com&pinSHA256=AD:B4:CD:0D:E2:66:8F:8E:9B:3C:E7:E3:5C:2A:5A:7A:3C:2A:5A:7A:3C:2A:5A:7A:3C:2A:5A:7A:3C:2A:5A:7A#pin"
	_, err := ray2sing.Hysteria2Singbox(link)
	if err == nil || !strings.Contains(err.Error(), "pinSHA256") {
		t.Errorf("pinSHA256 must fail conversion with a readable reason (got err=%v)", err)
	}
}

// ---------------------------------------------------------------------------
// hysteria2 up=/down= with units ("100 mbps") — the official hy2 config
// bandwidth format, accepted in URI form by the reference client. Atoi fails
// -> silent drop -> Brutal never engages though the user declared bandwidth.
// ---------------------------------------------------------------------------

func TestSweepQuic_Hy2BandwidthUnits(t *testing.T) {
	ho := qsHy2(t, "hysteria2://pw@example.com:443?sni=x.example.com&up=100%20mbps&down=500%20mbps#bw")
	if ho.UpMbps != 100 || ho.DownMbps != 500 {
		t.Errorf("up/down with units silently dropped: got up=%d down=%d, want 100/500", ho.UpMbps, ho.DownMbps)
	}
}

// Guard: plain numeric up/down works.
func TestSweepQuic_Hy2BandwidthPlainGuard(t *testing.T) {
	ho := qsHy2(t, "hysteria2://pw@example.com:443?sni=x.example.com&up=100&down=500#bwp")
	if ho.UpMbps != 100 || ho.DownMbps != 500 {
		t.Errorf("plain up/down mangled: got up=%d down=%d", ho.UpMbps, ho.DownMbps)
	}
}

// ---------------------------------------------------------------------------
// hysteria v1 protocol= vocabulary. Official v1 URI: protocol=udp (default) |
// wechat-video | faketcp. sing-box's hysteria outbound is UDP-only (no
// protocol field at all) — converting a faketcp/wechat-video link into a UDP
// hysteria node produces a server that can never answer. Must be a clear
// conversion-time rejection, not a silent wrong-protocol node.
// ---------------------------------------------------------------------------

func TestSweepQuic_Hy1ProtocolFaketcpRejected(t *testing.T) {
	outs, err := qsParse(t, "hysteria://example.com:443?auth=pw&upmbps=10&downmbps=50&protocol=faketcp#ftcp")
	if err == nil && len(outs) != 0 {
		t.Errorf("hysteria v1 protocol=faketcp silently converted to UDP hysteria (sing-box cannot faketcp) — node dials the wrong protocol forever")
	}
}

func TestSweepQuic_Hy1ProtocolUdpGuard(t *testing.T) {
	o := qsOne(t, "hysteria://example.com:443?auth=pw&upmbps=10&downmbps=50&protocol=udp#udp")
	if o.Type != "hysteria" {
		t.Errorf("protocol=udp (the default) must still parse, got type %s", o.Type)
	}
}

// ---------------------------------------------------------------------------
// tuic — disable_sni=1 (sing-box outbound field, emitted by NekoBox/sublink
// exports) is not read at all: the parser instead back-fills SNI from the
// connect host, so the client SENDS an SNI the link explicitly disabled.
// ---------------------------------------------------------------------------

func TestSweepQuic_TuicDisableSNI(t *testing.T) {
	o := qsOne(t, "tuic://00000000-0000-0000-0000-000000000001:pass@example.com:443?congestion_control=bbr&disable_sni=1#dsni")
	to := o.Options.(*option.TUICOutboundOptions)
	if to.TLS == nil || !to.TLS.DisableSNI {
		t.Errorf("disable_sni=1 ignored; SNI %q will be sent although the link disabled it", to.TLS.ServerName)
	}
}

// ---------------------------------------------------------------------------
// tuic v4 (token form, tuic://TOKEN@host:port?version=4). sing-box is v5-only
// and validates UUID at creation (protocol/tuic/outbound.go:55) — the token
// fails uuid.FromString and our fork swaps the node for InvalidConfig
// SILENTLY. A v4 link must be rejected at conversion with a diagnosable
// reason, not become an always-dead node.
// ---------------------------------------------------------------------------

func TestSweepQuic_TuicV4TokenRejectedAtConversion(t *testing.T) {
	outs, err := qsParse(t, "tuic://sometoken123@example.com:443?version=4&alpn=h3#v4")
	if err == nil && len(outs) != 0 {
		to := outs[0].Options.(*option.TUICOutboundOptions)
		t.Errorf("tuic v4 token link converted (uuid=%q) — dies later at uuid.FromString as a silent InvalidConfig; reject at conversion instead", to.UUID)
	}
}

// Guard: v5 uuid:password form with multi-value alpn.
func TestSweepQuic_TuicV5Guard(t *testing.T) {
	o := qsOne(t, "tuic://00000000-0000-0000-0000-000000000001:pass@example.com:443?congestion_control=bbr&alpn=h3,spdy/3.1&sni=x.example.com#v5")
	to := o.Options.(*option.TUICOutboundOptions)
	if to.UUID != "00000000-0000-0000-0000-000000000001" || to.Password != "pass" {
		t.Errorf("v5 creds mangled: uuid=%q pass=%q", to.UUID, to.Password)
	}
	if len(to.TLS.ALPN) != 2 || to.TLS.ALPN[0] != "h3" || to.TLS.ALPN[1] != "spdy/3.1" {
		t.Errorf("multi-value alpn mangled: %v", to.TLS.ALPN)
	}
}

// ---------------------------------------------------------------------------
// socks — v2rayN/NekoBox export the userinfo as base64("user:pass")
// (socks://dXNlcjpwYXNz@host:port#name). ParseUrl only applies the base64
// userinfo heuristic to ss://, so the blob becomes the literal username and
// the password is empty -> auth always fails.
// ---------------------------------------------------------------------------

func TestSweepQuic_SocksBase64Userinfo(t *testing.T) {
	// base64("user:pass") = dXNlcjpwYXNz
	o := qsOne(t, "socks://dXNlcjpwYXNz@example.com:1080#v2rayn")
	so := o.Options.(*option.SOCKSOutboundOptions)
	if so.Username != "user" || so.Password != "pass" {
		t.Errorf("v2rayN base64 userinfo not decoded: username=%q password=%q (auth will fail)", so.Username, so.Password)
	}
}

// Guards: plain userinfo and bare no-auth host keep working.
func TestSweepQuic_SocksPlainFormsGuard(t *testing.T) {
	o := qsOne(t, "socks5://user:pass@example.com:1080#plain")
	so := o.Options.(*option.SOCKSOutboundOptions)
	if so.Username != "user" || so.Password != "pass" || so.Version != "5" {
		t.Errorf("plain socks5 userinfo mangled: %q/%q v=%q", so.Username, so.Password, so.Version)
	}
	o2 := qsOne(t, "socks://example.com:1080#noauth")
	so2 := o2.Options.(*option.SOCKSOutboundOptions)
	if so2.Username != "" || so2.Password != "" {
		t.Errorf("bare no-auth socks grew credentials: %q/%q", so2.Username, so2.Password)
	}
}

// ---------------------------------------------------------------------------
// https:// proxy without an explicit port — ParseUrl(url, 0) leaves
// server_port 0 (dial fails at runtime). Scheme default is 443 (80 for http;
// the http/socks cases are covered in zz_sweep_envelope_test.go — same root
// cause, HttpsSingbox is a separate function so it gets its own repro).
// ---------------------------------------------------------------------------

func TestSweepQuic_HttpsMissingPortDefaults443(t *testing.T) {
	o := qsOne(t, "https://user:pass@proxy.example.com#hs")
	ho := o.Options.(*option.HTTPOutboundOptions)
	if ho.ServerPort == 0 {
		t.Errorf("portless https proxy yields server_port=0 (dead node); should default 443")
	}
}

// ---------------------------------------------------------------------------
// naive — userinfo with percent-encoded specials must survive (guard), and
// the naive+https scheme variant must parse (guard).
// ---------------------------------------------------------------------------

func TestSweepQuic_NaiveUserinfoSpecialsGuard(t *testing.T) {
	o := qsOne(t, "naive+https://user%40mail.com:p%40ss%3Aword@example.com:443#nv")
	no := o.Options.(*option.NaiveOutboundOptions)
	if no.Username != "user@mail.com" || no.Password != "p@ss:word" {
		t.Errorf("naive percent-encoded creds mangled: %q / %q", no.Username, no.Password)
	}
	if no.TLS == nil || !no.TLS.Enabled {
		t.Errorf("naive must always carry TLS")
	}
}

// ---------------------------------------------------------------------------
// anytls / dnstt / mieru guards for shapes in this sweep's scope.
// ---------------------------------------------------------------------------

func TestSweepQuic_AnyTLSColonPasswordGuard(t *testing.T) {
	o := qsOne(t, "anytls://part1:part2@example.com:443?sni=x.example.com#atls")
	ao := o.Options.(*option.AnyTLSOutboundOptions)
	if ao.Password != "part1:part2" {
		t.Errorf("anytls colon password truncated: %q", ao.Password)
	}
}

func TestSweepQuic_DnsttMissingPubkeyClearError(t *testing.T) {
	outs, err := qsParse(t, "dnstt://t.example.com?resolver=8.8.8.8:53#dt")
	if err == nil && len(outs) != 0 {
		t.Errorf("dnstt without pubkey must not produce an outbound")
	}
}

func TestSweepQuic_MieruAuthorityPortOnlyGuard(t *testing.T) {
	o := qsOne(t, "mierus://user:pass@example.com:6666#mr")
	mo := o.Options.(*option.MieruOutboundOptions)
	if len(mo.PortBindings) != 1 || mo.PortBindings[0].Port != 6666 || !strings.EqualFold(mo.PortBindings[0].Protocol, "TCP") {
		t.Errorf("minimal mieru link mangled: %+v", mo.PortBindings)
	}
}
