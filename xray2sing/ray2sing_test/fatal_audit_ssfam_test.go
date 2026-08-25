// fatal_audit_ssfam_test.go — regression tests for the 2026-08 fatal-outbound
// audit, "ssfam" findings group: shadowsocks family (ss/ss2022/plugins),
// shadowtls, beepass/ssconf, and the Clash YAML ingest container.
package ray2sing_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	T "github.com/sagernet/sing-box/option"
	"github.com/twilgate/xray2sing/ray2sing"
)

func ssOptions(t *testing.T, link string) *T.ShadowsocksOutboundOptions {
	t.Helper()
	out, err := ray2sing.ShadowsocksSingbox(link)
	if err != nil {
		t.Fatalf("ShadowsocksSingbox(%q) error: %v", link, err)
	}
	opts, ok := out.Options.(*T.ShadowsocksOutboundOptions)
	if !ok {
		t.Fatalf("options type %T, want *ShadowsocksOutboundOptions", out.Options)
	}
	return opts
}

// Finding: clash_ingest.go:119 — one type-mismatched YAML field in ANY single
// Clash proxy rejected the ENTIRE subscription. *yaml.TypeError is a partial
// decode: the other proxies are fully populated and must survive.
func TestClashYAMLTypeErrorLosesOneNodeNotSubscription(t *testing.T) {
	yaml := "proxies:\n" +
		"  - {name: ok, type: trojan, server: a.com, port: 443, password: p}\n" +
		"  - {name: bad, type: trojan, server: b.com, port: \"8443\", password: p}\n"
	out, err := ray2sing.ConvertToShareLinks(yaml)
	if err != nil {
		t.Fatalf("ConvertToShareLinks error (whole subscription rejected): %v", err)
	}
	if !strings.Contains(out, "a.com") {
		t.Fatalf("valid proxy a.com lost from output: %q", out)
	}
	if strings.Contains(out, "b.com") {
		t.Fatalf("half-decoded proxy b.com should have been dropped: %q", out)
	}
}

// Finding: shadowsocks.go:46 — foreign cipher vocabulary (Xray/v2ray/rust
// spellings) must be normalized to the sing-shadowsocks2 registry names.
func TestSSMethodAliasesNormalized(t *testing.T) {
	cases := []struct{ in, want string }{
		{"chacha20-poly1305", "chacha20-ietf-poly1305"},
		{"xchacha20-poly1305", "xchacha20-ietf-poly1305"},
		{"aead_chacha20_poly1305", "chacha20-ietf-poly1305"},
		{"aead_aes_128_gcm", "aes-128-gcm"},
		{"aead_aes_256_gcm", "aes-256-gcm"},
		{"plain", "none"},
		{"dummy", "none"},
		{"AES-256-GCM", "aes-256-gcm"}, // lowercase before matching
	}
	for _, c := range cases {
		opts := ssOptions(t, "ss://"+c.in+":password123@1.2.3.4:8388#node")
		if opts.Method != c.want {
			t.Errorf("method %q normalized to %q, want %q", c.in, opts.Method, c.want)
		}
	}
}

// Finding: clash_ingest.go:368 / shadowsocks.go:46 — ciphers sing-shadowsocks2
// genuinely lacks must produce a clear parser error naming the cipher, not an
// "unknown method" invalid stub at outbound creation.
func TestSSMethodUnsupportedErrorsNameCipher(t *testing.T) {
	for _, cipher := range []string{"chacha8-ietf-poly1305", "aegis-128l", "aes-128-gcm-siv", "rabbit128-poly1305", "lea-256-gcm", "chacha20"} {
		_, err := ray2sing.ShadowsocksSingbox("ss://" + cipher + ":password123@1.2.3.4:8388#node")
		if err == nil {
			t.Errorf("cipher %q: expected error, got nil", cipher)
			continue
		}
		if !strings.Contains(err.Error(), strings.ToLower(cipher)) {
			t.Errorf("cipher %q: error does not name the cipher: %v", cipher, err)
		}
	}
}

// Finding: shadowsocks.go:47 — ss2022 PSK in URL-safe base64 fails the
// StdEncoding-only key decode in sing-shadowsocks2; canonicalize per segment.
func TestSS2022PSKURLSafeBase64Canonicalized(t *testing.T) {
	opts := ssOptions(t, "ss://2022-blake3-aes-256-gcm:pXmJit3fmAIGcEfZcx_r2leaqIqi5yabk4wfvAHIJVY=@1.2.3.4:8388#node")
	if opts.Password != "pXmJit3fmAIGcEfZcx/r2leaqIqi5yabk4wfvAHIJVY=" {
		t.Fatalf("url-safe PSK not canonicalized to std base64: %q", opts.Password)
	}
	// A non-2022 password must never be touched (it is a plaintext passphrase).
	opts = ssOptions(t, "ss://aes-256-gcm:my_pass-word@1.2.3.4:8388#node")
	if opts.Password != "my_pass-word" {
		t.Fatalf("plain ss password mangled: %q", opts.Password)
	}
}

// Finding: shadowsocks.go:48 — SIP003 plugin names from foreign vocab must be
// aliased to the two registered sing-box plugins; unknown ones must error
// clearly instead of dying with "plugin not found" at creation.
func TestSSPluginAliasesAndUnknownRejected(t *testing.T) {
	opts := ssOptions(t, "ss://aes-256-gcm:password123@1.2.3.4:8388/?plugin=simple-obfs%3Bobfs%3Dhttp%3Bobfs-host%3Dwww.bing.com#node")
	if opts.Plugin != "obfs-local" {
		t.Errorf("simple-obfs aliased to %q, want obfs-local", opts.Plugin)
	}
	if opts.PluginOptions != "obfs=http;obfs-host=www.bing.com" {
		t.Errorf("plugin options lost: %q", opts.PluginOptions)
	}
	opts = ssOptions(t, "ss://aes-256-gcm:password123@1.2.3.4:8388/?plugin=obfs%3Bobfs%3Dtls#node")
	if opts.Plugin != "obfs-local" {
		t.Errorf("obfs aliased to %q, want obfs-local", opts.Plugin)
	}
	opts = ssOptions(t, "ss://aes-256-gcm:password123@1.2.3.4:8388/?plugin=xray-plugin%3Btls#node")
	if opts.Plugin != "v2ray-plugin" {
		t.Errorf("xray-plugin aliased to %q, want v2ray-plugin", opts.Plugin)
	}
	for _, plugin := range []string{"shadow-tls", "restls", "gost-plugin"} {
		_, err := ray2sing.ShadowsocksSingbox("ss://aes-256-gcm:password123@1.2.3.4:8388/?plugin=" + plugin + "#node")
		if err == nil || !strings.Contains(err.Error(), plugin) {
			t.Errorf("plugin %q: expected error naming the plugin, got %v", plugin, err)
		}
	}
}

// Finding: shadowtls.go:29 — version passed through unclamped; sing-shadowtls
// accepts exactly {1,2,3}, anything else was rejected at outbound creation.
func TestShadowTLSVersionClamp(t *testing.T) {
	cases := []struct {
		q    string
		want int
	}{
		{"version=4", 3},
		{"version=-1", 3},
		{"version=99", 3},
		{"", 3},
		{"version=2", 2},
		{"version=1", 1},
	}
	for _, c := range cases {
		out, err := ray2sing.ShadowTLSSingbox("shadowtls://password@1.2.3.4:443?" + c.q + "#node")
		if err != nil {
			t.Fatalf("ShadowTLSSingbox(%q) error: %v", c.q, err)
		}
		opts := out.Options.(*T.ShadowTLSOutboundOptions)
		if opts.Version != c.want {
			t.Errorf("query %q: version %d, want %d", c.q, opts.Version, c.want)
		}
	}
}

// Finding: shadowtls.go:35 — explicit security=none in the link defeated the
// TLS seed, and the outbound died with ErrTLSRequired. ShadowTLS is
// definitionally TLS; only reality may take over the block.
func TestShadowTLSSecurityNoneStillGetsTLS(t *testing.T) {
	for _, q := range []string{"security=none", "tls=none", "security=false", ""} {
		out, err := ray2sing.ShadowTLSSingbox("shadowtls://password@1.2.3.4:443?version=3&sni=cloud.example.com&" + q + "#node")
		if err != nil {
			t.Fatalf("ShadowTLSSingbox(%q) error: %v", q, err)
		}
		opts := out.Options.(*T.ShadowTLSOutboundOptions)
		if opts.TLS == nil || !opts.TLS.Enabled {
			t.Errorf("query %q: TLS block missing/disabled — outbound would die with ErrTLSRequired", q)
		}
	}
}

// Finding: beepass.go:16 — ServerPort typed string rejected the numeric
// server_port that spec-conformant Outline/BeePass dynamic keys return.
func TestBeepassNumericAndStringServerPort(t *testing.T) {
	for _, body := range []string{
		`{"server":"1.2.3.4","server_port":8388,"password":"pw","method":"chacha20-ietf-poly1305"}`,
		`{"server":"1.2.3.4","server_port":"8388","password":"pw","method":"chacha20-ietf-poly1305"}`,
	} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(body))
		}))
		u, _ := url.Parse(srv.URL)
		old := ray2sing.SSConfHTTPClient
		ray2sing.SSConfHTTPClient = srv.Client()
		out, err := ray2sing.BeepassSingbox("ssconf://" + u.Host + "/conf#BeePass")
		ray2sing.SSConfHTTPClient = old
		srv.Close()
		if err != nil {
			t.Fatalf("BeepassSingbox error for body %s: %v", body, err)
		}
		opts := out.Options.(*T.ShadowsocksOutboundOptions)
		if opts.ServerPort != 8388 {
			t.Errorf("body %s: port %d, want 8388", body, opts.ServerPort)
		}
		if opts.Method != "chacha20-ietf-poly1305" || opts.Server != "1.2.3.4" || out.Tag != "BeePass" {
			t.Errorf("body %s: decoded fields wrong: %+v tag=%q", body, opts, out.Tag)
		}
	}
}

// Finding: beepass.go:28 — bare http.Get had no timeout; one dead ssconf://
// link stalled conversion of the whole subscription. The fetch must go through
// the bounded package client.
func TestBeepassFetchIsBounded(t *testing.T) {
	if ray2sing.SSConfHTTPClient.Timeout <= 0 {
		t.Fatal("SSConfHTTPClient has no timeout — a dead ssconf endpoint hangs forever")
	}
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release // tarpit: never answer until the test ends
	}))
	defer func() { close(release); srv.Close() }()
	u, _ := url.Parse(srv.URL)

	bounded := srv.Client()
	bounded.Timeout = 200 * time.Millisecond
	old := ray2sing.SSConfHTTPClient
	ray2sing.SSConfHTTPClient = bounded
	defer func() { ray2sing.SSConfHTTPClient = old }()

	start := time.Now()
	_, err := ray2sing.BeepassSingbox("ssconf://" + u.Host + "/conf#BeePass")
	if err == nil {
		t.Fatal("expected timeout error from tarpit endpoint, got nil")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("fetch not bounded by the client timeout: took %v", elapsed)
	}
}

// Finding: clash_ingest.go:368/379 — mihomo-only ciphers and plugins must be
// skip()ed at ingest with a readable reason, so a whole-fleet sub of them can
// never reach outbound creation and trip the all-invalid profile gate, while
// the servable nodes in the same sub survive.
func TestClashSSUnsupportedCipherAndPluginSkipped(t *testing.T) {
	yaml := "proxies:\n" +
		"  - {name: ok, type: ss, server: a.com, port: 443, cipher: aes-256-gcm, password: p}\n" +
		"  - {name: badcipher, type: ss, server: b.com, port: 443, cipher: chacha8-ietf-poly1305, password: p}\n" +
		"  - {name: badplugin, type: ss, server: c.com, port: 443, cipher: aes-256-gcm, password: p, plugin: shadow-tls, plugin-opts: {host: cloud.example, password: pw, version: 3}}\n"
	out, err := ray2sing.ConvertToShareLinks(yaml)
	if err != nil {
		t.Fatalf("ConvertToShareLinks error: %v", err)
	}
	if !strings.Contains(out, "a.com") {
		t.Fatalf("supported ss node a.com lost: %q", out)
	}
	if strings.Contains(out, "b.com") || strings.Contains(out, "c.com") {
		t.Fatalf("unsupported cipher/plugin node not skipped: %q", out)
	}
}

// The Clash "obfs" plugin spelling (and simple-obfs) must survive ingest and
// come out as the registered obfs-local plugin end-to-end.
func TestClashSSObfsPluginAliasedEndToEnd(t *testing.T) {
	yaml := "proxies:\n" +
		"  - {name: n1, type: ss, server: a.com, port: 443, cipher: aes-256-gcm, password: p, plugin: obfs, plugin-opts: {mode: http, host: www.bing.com}}\n"
	out, err := ray2sing.ConvertToShareLinks(yaml)
	if err != nil {
		t.Fatalf("ConvertToShareLinks error: %v", err)
	}
	if !strings.Contains(out, "obfs-local") {
		t.Fatalf("clash obfs plugin not aliased to obfs-local: %q", out)
	}
}
