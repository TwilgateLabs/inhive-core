package ray2sing_test

// Audit 2026-08-25 (proto findings group): parser-level regression tests for the
// vocabulary-passthrough / prefix / duration fixes in vless/vmess/tuic/ssh/
// socks/naive/mieru and the json_ingest Happ-vmess rename path.

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"github.com/twilgate/xray2sing/ray2sing"
)

// parseOne runs one subscription body through GenerateConfigLite and returns
// the single resulting outbound.
func parseOne(t *testing.T, input string) option.Outbound {
	t.Helper()
	opts, err := ray2sing.GenerateConfigLite(input, false)
	if err != nil {
		t.Fatalf("GenerateConfigLite(%q): %v", input, err)
	}
	if len(opts.Outbounds) != 1 {
		t.Fatalf("GenerateConfigLite(%q): want 1 outbound, got %d", input, len(opts.Outbounds))
	}
	return opts.Outbounds[0]
}

// parseRejected asserts the single config is rejected (its parser errored, so
// the subscription yields zero outbounds).
func parseRejected(t *testing.T, input string) {
	t.Helper()
	opts, err := ray2sing.GenerateConfigLite(input, false)
	if err == nil {
		t.Fatalf("GenerateConfigLite(%q): expected rejection, got %d outbounds", input, len(opts.Outbounds))
	}
}

const testUUID = "11111111-2222-3333-4444-555555555555"

// ---- Finding 1/5: VLESS flow normalization (vless.go + json_ingest vless) ----

func vlessFlowOf(t *testing.T, uri string) string {
	t.Helper()
	ob := parseOne(t, uri)
	o, ok := ob.Options.(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("not VLESS options: %T", ob.Options)
	}
	return o.Flow
}

func TestVlessFlowNoneMapsToEmpty(t *testing.T) {
	if f := vlessFlowOf(t, "vless://"+testUUID+"@example.com:443?security=tls&type=tcp&flow=none#t"); f != "" {
		t.Fatalf("flow=none: want \"\", got %q", f)
	}
	// value is not case-normalized upstream — "None" must work too
	if f := vlessFlowOf(t, "vless://"+testUUID+"@example.com:443?security=tls&type=tcp&flow=None#t"); f != "" {
		t.Fatalf("flow=None: want \"\", got %q", f)
	}
}

func TestVlessFlowVisionUDP443Alias(t *testing.T) {
	if f := vlessFlowOf(t, "vless://"+testUUID+"@example.com:443?security=tls&type=tcp&flow=xtls-rprx-vision-udp443#t"); f != "xtls-rprx-vision" {
		t.Fatalf("want xtls-rprx-vision, got %q", f)
	}
	if f := vlessFlowOf(t, "vless://"+testUUID+"@example.com:443?security=tls&type=tcp&flow=XTLS-RPRX-Vision#t"); f != "xtls-rprx-vision" {
		t.Fatalf("uppercase vision: want xtls-rprx-vision, got %q", f)
	}
}

func TestVlessFlowLegacyXTLSRejected(t *testing.T) {
	for _, flow := range []string{"xtls-rprx-direct", "xtls-rprx-origin", "xtls-rprx-splice", "xtls-rprx-direct-udp443"} {
		parseRejected(t, "vless://"+testUUID+"@example.com:443?security=tls&type=tcp&flow="+flow+"#t")
	}
}

func TestVlessFlowUnknownRejected(t *testing.T) {
	parseRejected(t, "vless://"+testUUID+"@example.com:443?security=tls&type=tcp&flow=bogus-flow#t")
}

func TestVlessJSONFlowNoneNormalized(t *testing.T) {
	body := `{"outbounds":[{"protocol":"vless","tag":"x","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"` + testUUID + `","flow":"none","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"tls"}}]}`
	ob := parseOne(t, body)
	o := ob.Options.(*option.VLESSOutboundOptions)
	if o.Flow != "" {
		t.Fatalf("JSON flow=none: want \"\", got %q", o.Flow)
	}
}

// ---- Finding 2: decodeVmess scheme-agnostic prefix (svmess/xvmess) ----

func vmessB64(fields map[string]string) string {
	j, _ := json.Marshal(fields)
	return base64.StdEncoding.EncodeToString(j)
}

func baseVmessFields() map[string]string {
	return map[string]string{
		"v": "2", "ps": "t", "add": "example.com", "port": "443",
		"id": testUUID, "aid": "0", "net": "tcp",
	}
}

func TestVmessNineCharSchemes(t *testing.T) {
	b64 := vmessB64(baseVmessFields())
	for _, scheme := range []string{"vmess://", "svmess://", "xvmess://"} {
		ob := parseOne(t, scheme+b64)
		o, ok := ob.Options.(*option.VMessOutboundOptions)
		if !ok {
			t.Fatalf("%s: not VMess options: %T", scheme, ob.Options)
		}
		if o.Server != "example.com" || o.ServerPort != 443 {
			t.Fatalf("%s: bad server %s:%d", scheme, o.Server, o.ServerPort)
		}
	}
}

// ---- Finding 3: vmess scy normalization ----

func vmessSecurityOf(t *testing.T, scy string) string {
	t.Helper()
	f := baseVmessFields()
	if scy != "" {
		f["scy"] = scy
	}
	ob := parseOne(t, "vmess://"+vmessB64(f))
	return ob.Options.(*option.VMessOutboundOptions).Security
}

func TestVmessSecurityNormalization(t *testing.T) {
	cases := map[string]string{
		"":                       "auto",
		"AES-128-GCM":            "aes-128-gcm",
		"Auto":                   "auto",
		"chacha20-ietf-poly1305": "chacha20-poly1305",
		"aes-256-gcm":            "auto", // unknown to sing-vmess -> auto (Xray parity)
		"zero":                   "zero",
		"none":                   "none",
	}
	for in, want := range cases {
		if got := vmessSecurityOf(t, in); got != want {
			t.Fatalf("scy %q: want %q, got %q", in, want, got)
		}
	}
}

// ---- Finding 4: vmess://b64#fragment (Happ rename + share-link name) ----

func TestVmessFragmentStrippedAndUsedAsName(t *testing.T) {
	uri := "vmess://" + vmessB64(baseVmessFields()) + "#My%20Server"
	ob := parseOne(t, uri)
	if !strings.HasPrefix(ob.Tag, "My Server") {
		t.Fatalf("fragment not used as name: tag %q", ob.Tag)
	}
}

func TestHappVmessRenameSurvives(t *testing.T) {
	// Happ per-node wrapper: rename appends #fragment to the rebuilt
	// vmess://base64 URI; decodeVmess must strip it before base64-decoding.
	body := `[{"remarks":"Мой сервер","outbounds":[{"protocol":"vmess","tag":"proxy","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"` + testUUID + `","alterId":0,"security":"auto"}]}]},"streamSettings":{"network":"ws","security":"tls","wsSettings":{"path":"/ws","host":"cdn.example.com"}}}]}]`
	ob := parseOne(t, body)
	o, ok := ob.Options.(*option.VMessOutboundOptions)
	if !ok {
		t.Fatalf("not VMess options: %T", ob.Options)
	}
	if o.Server != "1.2.3.4" {
		t.Fatalf("bad server %q", o.Server)
	}
	if !strings.HasPrefix(ob.Tag, "Мой сервер") {
		t.Fatalf("Happ rename lost: tag %q", ob.Tag)
	}
}

// ---- Finding 6: ss method "plain"/case via JSON + SIP008 ----

func TestSSMethodPlainNormalized(t *testing.T) {
	xray := `{"outbounds":[{"protocol":"shadowsocks","tag":"s","settings":{"servers":[{"address":"1.2.3.4","port":8388,"method":"plain","password":"pw"}]}}]}`
	ob := parseOne(t, xray)
	o := ob.Options.(*option.ShadowsocksOutboundOptions)
	if o.Method != "none" {
		t.Fatalf("xray-json method plain: want none, got %q", o.Method)
	}

	sip008 := `{"version":1,"servers":[{"server":"1.2.3.4","server_port":8388,"method":"PLAIN","password":"pw","remarks":"r"}]}`
	ob = parseOne(t, sip008)
	o = ob.Options.(*option.ShadowsocksOutboundOptions)
	if o.Method != "none" {
		t.Fatalf("sip008 method PLAIN: want none, got %q", o.Method)
	}
}

// ---- Finding 7: naive security=none + quic_congestion_control ----

func TestNaiveSecurityNoneStillTLS(t *testing.T) {
	ob := parseOne(t, "naive+https://user:pass@example.com:443?security=none#srv")
	o := ob.Options.(*option.NaiveOutboundOptions)
	if o.TLS == nil || !o.TLS.Enabled {
		t.Fatalf("naive with security=none must still carry enabled TLS, got %+v", o.TLS)
	}
}

func TestNaiveQUICCongestionControlNormalized(t *testing.T) {
	cases := map[string]string{
		"BBR":     "bbr",
		"bbrv2":   "bbr2",
		"BBRv2":   "bbr2",
		"cubic":   "cubic",
		"garbage": "",
	}
	for in, want := range cases {
		ob := parseOne(t, "naive+quic://user:pass@example.com:443?quic_congestion_control="+in+"#srv")
		o := ob.Options.(*option.NaiveOutboundOptions)
		if o.QUICCongestionControl != want {
			t.Fatalf("qcc %q: want %q, got %q", in, want, o.QUICCongestionControl)
		}
	}
}

// ---- Finding 8: socks version normalization ----

func TestSocksVersionNormalized(t *testing.T) {
	cases := map[string]string{
		"4A":      "4a",
		"4a":      "4a",
		"5h":      "5",
		"socks5":  "5",
		"socks4a": "4a",
		"5":       "5",
	}
	for in, want := range cases {
		ob := parseOne(t, "socks://user:pass@1.2.3.4:1080?version="+in+"#srv")
		o := ob.Options.(*option.SOCKSOutboundOptions)
		if o.Version != want {
			t.Fatalf("version %q: want %q, got %q", in, want, o.Version)
		}
	}
}

func TestSocksVersionUnknownRejected(t *testing.T) {
	parseRejected(t, "socks://user:pass@1.2.3.4:1080?version=6#srv")
}

// ---- Finding 9: ssh pk_passphrase / client_version lookups ----

func TestSSHUnderscoreParams(t *testing.T) {
	ob := parseOne(t, "ssh://root@1.2.3.4:22?pk=aaa&pk_passphrase=secret123&client_version=SSH-2.0-x#srv")
	o := ob.Options.(*option.SSHOutboundOptions)
	if o.PrivateKeyPassphrase != "secret123" {
		t.Fatalf("pk_passphrase lost: got %q", o.PrivateKeyPassphrase)
	}
	if o.ClientVersion != "SSH-2.0-x" {
		t.Fatalf("client_version lost: got %q", o.ClientVersion)
	}
}

// ---- Finding 10: mieru protocol default + mtu clamp ----

func TestMieruMissingProtocolDefaultsTCP(t *testing.T) {
	ob := parseOne(t, "mierus://user:pass@1.2.3.4:6666#srv")
	o := ob.Options.(*option.MieruOutboundOptions)
	if len(o.PortBindings) != 1 || o.PortBindings[0].Protocol != "TCP" {
		t.Fatalf("want single TCP binding, got %+v", o.PortBindings)
	}
	if o.PortBindings[0].Port != 6666 {
		t.Fatalf("want authority port 6666, got %d", o.PortBindings[0].Port)
	}
}

func TestMieruMTUClamp(t *testing.T) {
	cases := map[string]int32{
		"1200": 0,    // below range -> library default
		"9000": 0,    // above range -> library default
		"1400": 1400, // in range -> kept
	}
	for in, want := range cases {
		ob := parseOne(t, "mierus://user:pass@1.2.3.4:6666?protocol=TCP&mtu="+in+"#srv")
		o := ob.Options.(*option.MieruOutboundOptions)
		if o.MTU != want {
			t.Fatalf("mtu %s: want %d, got %d", in, want, o.MTU)
		}
	}
}

// ---- Finding 11: tuic heartbeat must never reach time.NewTicker <= 0 ----

func tuicHeartbeatOf(t *testing.T, hb string) badoption.Duration {
	t.Helper()
	uri := "tuic://" + testUUID + ":pass@example.com:443"
	if hb != "" {
		uri += "?heartbeat=" + hb
	}
	uri += "#n"
	ob := parseOne(t, uri)
	return ob.Options.(*option.TUICOutboundOptions).Heartbeat
}

func TestTuicHeartbeatGuard(t *testing.T) {
	def := badoption.Duration(10 * time.Second)
	cases := map[string]badoption.Duration{
		"":            def,
		"-1":          def, // negative Atoi -> default (NewTicker panics on <=0)
		"0":           def,
		"10000000000": def, // int64 overflow-to-negative via *time.Second
		"-5s":         def, // negative ParseDuration -> default
		"5":           badoption.Duration(5 * time.Second),
		"30s":         badoption.Duration(30 * time.Second),
	}
	for in, want := range cases {
		if got := tuicHeartbeatOf(t, in); got != want {
			t.Fatalf("heartbeat %q: want %v, got %v", in, time.Duration(want), time.Duration(got))
		}
	}
}
