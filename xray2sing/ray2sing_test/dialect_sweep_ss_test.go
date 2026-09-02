// zz_sweep_ss_test.go — 2026-09-02 sweep: real-world Shadowsocks link shapes
// (Outline, shadowsocks-rust sslocal, v2rayN, Shadowrocket, старые ss-панели,
// SIP002/SIP008 specs) against shadowsocks.go / url_schema.go / beepass.go.
// Failing tests are CONFIRMED findings (left failing on purpose); passing ones
// are guards documenting shapes that already survive.
package ray2sing_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/twilgate/xray2sing/ray2sing"
)

func zzStdB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// zzSSParse pushes one link through the full pipeline (the path the app uses).
func zzSSParse(t *testing.T, link string) (*option.ShadowsocksOutboundOptions, string) {
	t.Helper()
	opts, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), link, false)
	if err != nil {
		t.Fatalf("parse failed for %q: %v", link, err)
	}
	if len(opts.Outbounds) == 0 {
		t.Fatalf("no outbounds parsed from %q", link)
	}
	o := opts.Outbounds[0]
	so, ok := o.Options.(*option.ShadowsocksOutboundOptions)
	if !ok {
		t.Fatalf("outbound for %q is %T, want *ShadowsocksOutboundOptions", link, o.Options)
	}
	return so, o.Tag
}

func zzAssertSS(t *testing.T, link, method, password, server string, port uint16) {
	t.Helper()
	so, _ := zzSSParse(t, link)
	if so.Method != method {
		t.Errorf("link %q: method %q, want %q", link, so.Method, method)
	}
	if so.Password != password {
		t.Errorf("link %q: password %q, want %q", link, so.Password, password)
	}
	if so.Server != server {
		t.Errorf("link %q: server %q, want %q", link, so.Server, server)
	}
	if so.ServerPort != port {
		t.Errorf("link %q: port %d, want %d", link, so.ServerPort, port)
	}
}

// ---------------------------------------------------------------------------
// A. Legacy whole-base64 form: ss://BASE64(method:password@host:port)#tag
//    (pre-SIP002; Shadowrocket "copy" and old ss-panels still emit it)
// ---------------------------------------------------------------------------

// Plain-charset password: std base64, padded, with tag — the common shape.
func TestSweepSSLegacyBase64Basic(t *testing.T) {
	link := "ss://" + zzStdB64("aes-256-cfb:barfoo!@1.2.3.4:8388") + "#legacy-node"
	zzAssertSS(t, link, "aes-256-cfb", "barfoo!", "1.2.3.4", 8388)
	so, tag := zzSSParse(t, link)
	_ = so
	if !strings.HasPrefix(tag, "legacy-node") {
		t.Errorf("tag %q, want prefix legacy-node", tag)
	}
}

// Shadowrocket emits URL-safe base64 without padding for the legacy body.
func TestSweepSSLegacyBase64URLSafeNoPadding(t *testing.T) {
	body := base64.RawURLEncoding.EncodeToString([]byte("chacha20-ietf-poly1305:s3cr3t@vpn.example.com:443"))
	zzAssertSS(t, "ss://"+body+"#sr", "chacha20-ietf-poly1305", "s3cr3t", "vpn.example.com", 443)
}

// Legacy body + SIP002-style query (plugin) appended outside the base64.
func TestSweepSSLegacyBase64WithPluginQuery(t *testing.T) {
	link := "ss://" + zzStdB64("aes-256-gcm:pw@1.2.3.4:8388") +
		"?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#n"
	so, _ := zzSSParse(t, link)
	if so.Plugin != "obfs-local" || so.PluginOptions != "obfs=http;obfs-host=bing.com" {
		t.Errorf("legacy+query plugin lost: plugin=%q opts=%q", so.Plugin, so.PluginOptions)
	}
}

// Legacy body with IPv6 host.
func TestSweepSSLegacyBase64IPv6(t *testing.T) {
	zzAssertSS(t, "ss://"+zzStdB64("aes-256-gcm:pw@[2001:db8::1]:8388")+"#v6",
		"aes-256-gcm", "pw", "2001:db8::1", 8388)
}

// THE ENTIRE POINT of the legacy form is that the password may contain URL
// metacharacters without any encoding (that is why old clients base64 the whole
// authority). normalizeLegacyShadowsocks rebuilds a plaintext URI from the
// decoded body WITHOUT percent-encoding the userinfo (shadowsocks.go:233), so
// every URL metacharacter in the password either kills the node (url.Parse
// error) or silently mangles password/host. shadowsocks-libev/ss-panels happily
// generate such passwords.
func TestSweepSSLegacyBase64SpecialCharPasswords(t *testing.T) {
	for _, pw := range []string{
		"pa/ss",  // '/' -> authority truncated at path
		"pa?ss",  // '?' -> password+host swallowed by query
		"pa#ss",  // '#' -> tail becomes fragment
		"pa%ss",  // '%' -> url.Parse invalid-escape error
		"p@ss",   // '@' -> Go splits userinfo at LAST '@' (may survive)
		"pa ss",  // space -> invalid userinfo char
		"pa&ss",  // '&' -> valid in userinfo (should survive)
		"пароль", // unicode -> invalid userinfo bytes
	} {
		link := "ss://" + zzStdB64("aes-256-cfb:"+pw+"@1.2.3.4:8388") + "#x"
		t.Run(pw, func(t *testing.T) {
			zzAssertSS(t, link, "aes-256-cfb", pw, "1.2.3.4", 8388)
		})
	}
}

// ---------------------------------------------------------------------------
// B. SIP002 plain (unencoded) userinfo — shadowsocks-rust sslocal accepts and
//    emits it; MANDATORY (only legal form) for 2022-* methods per SIP002.
// ---------------------------------------------------------------------------

// Every supported method in the plain "method:password@" form. Hazard under
// test: url_schema.go:55 runs the base64 heuristic on ANY ss:// username in
// the base64 charset — every method name matches base64CharRegex, and
// decodeBase64FaultTolerant pads and force-decodes it; if any method name
// happens to decode to printable text containing ':', the real credentials are
// silently replaced by garbage.
func TestSweepSSPlainUserinfoAllMethods(t *testing.T) {
	methods := []string{
		"none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
		"chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
		"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
		"aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
		"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
		"rc4-md5", "chacha20-ietf", "xchacha20",
	}
	for _, m := range methods {
		t.Run(m, func(t *testing.T) {
			pw := "Sup3rSecret"
			if strings.HasPrefix(m, "2022-") {
				pw = zzStdB64("0123456789abcdef0123456789abcdef") // valid-length PSK, std b64
			}
			zzAssertSS(t, "ss://"+m+":"+url.QueryEscape(pw)+"@1.2.3.4:8388#n", m, pw, "1.2.3.4", 8388)
		})
	}
	// 2022-blake3-chacha20-poly1305 separately (32-byte key PSK).
	psk := zzStdB64("abcdefghijklmnopqrstuvwxyz012345")
	zzAssertSS(t, "ss://2022-blake3-chacha20-poly1305:"+url.QueryEscape(psk)+"@1.2.3.4:8388#n",
		"2022-blake3-chacha20-poly1305", psk, "1.2.3.4", 8388)
}

// Percent-encoded password carrying '@' ':' '/' '?' '#' — SIP002-conformant
// encoding of an arbitrary passphrase.
func TestSweepSSPlainUserinfoPercentEncodedPassword(t *testing.T) {
	pw := "p@ss:w/rd?#&="
	zzAssertSS(t, "ss://aes-256-gcm:"+url.QueryEscape(pw)+"@1.2.3.4:8388#n",
		"aes-256-gcm", pw, "1.2.3.4", 8388)
}

// SIP002 says empty password is legal for method "none" ("ss://none:@h:p" or
// even "ss://none@h:p" per some emitters). shadowsocks.go:106-110 reuses the
// empty-password branch as the "userinfo is the whole password" fallback, so an
// EXPLICIT empty password turns the method into the password.
func TestSweepSSPlainNoneEmptyPassword(t *testing.T) {
	so, _ := zzSSParse(t, "ss://none:@1.2.3.4:8388#n")
	if so.Method != "none" {
		t.Errorf("method %q, want none", so.Method)
	}
	if so.Password != "" {
		t.Errorf("empty password mangled to %q", so.Password)
	}
}

// ---------------------------------------------------------------------------
// C. SIP002 base64 userinfo variants
// ---------------------------------------------------------------------------

// v2rayN emits base64url WITHOUT padding for the userinfo.
func TestSweepSSUserinfoBase64URLNoPadding(t *testing.T) {
	ui := base64.RawURLEncoding.EncodeToString([]byte("aes-256-gcm:pw+with/slash"))
	zzAssertSS(t, "ss://"+ui+"@1.2.3.4:8388#n", "aes-256-gcm", "pw+with/slash", "1.2.3.4", 8388)
}

// Std base64 userinfo with '=' padding percent-encoded (%3D) — SIP002 says
// userinfo padding must be percent-encoded when present.
func TestSweepSSUserinfoBase64PaddingPercentEncoded(t *testing.T) {
	ui := zzStdB64("aes-128-gcm:test") // "YWVzLTEyOC1nY206dGVzdA=="
	ui = strings.ReplaceAll(ui, "=", "%3D")
	zzAssertSS(t, "ss://"+ui+"@1.2.3.4:8388#n", "aes-128-gcm", "test", "1.2.3.4", 8388)
}

// ---------------------------------------------------------------------------
// D. Plugin option strings
// ---------------------------------------------------------------------------

// v2ray-plugin with semicolon opts incl. mode=websocket — opts must land in
// plugin_opts verbatim (sing-box's sip003 v2ray-plugin reads them itself).
func TestSweepSSV2rayPluginWebsocketOpts(t *testing.T) {
	link := "ss://aes-256-gcm:pw@1.2.3.4:443/?plugin=" +
		url.QueryEscape("v2ray-plugin;tls;mode=websocket;host=cdn.example.com;path=/ws") + "#n"
	so, _ := zzSSParse(t, link)
	if so.Plugin != "v2ray-plugin" {
		t.Errorf("plugin %q, want v2ray-plugin", so.Plugin)
	}
	if so.PluginOptions != "tls;mode=websocket;host=cdn.example.com;path=/ws" {
		t.Errorf("plugin opts mangled: %q", so.PluginOptions)
	}
}

// SIP002 backslash-escaped ';' inside an option value must NOT split the
// plugin name early (indexUnescaped guard).
func TestSweepSSPluginEscapedSemicolonInOpts(t *testing.T) {
	link := "ss://aes-256-gcm:pw@1.2.3.4:443/?plugin=" +
		url.QueryEscape(`obfs-local;obfs-host=a\;b`) + "#n"
	so, _ := zzSSParse(t, link)
	if so.Plugin != "obfs-local" {
		t.Errorf("plugin %q, want obfs-local", so.Plugin)
	}
	if so.PluginOptions != `obfs-host=a\;b` {
		t.Errorf("escaped-semicolon opts mangled: %q", so.PluginOptions)
	}
}

// ---------------------------------------------------------------------------
// E. Host / port / tag shapes
// ---------------------------------------------------------------------------

func TestSweepSSPlainIPv6Host(t *testing.T) {
	zzAssertSS(t, "ss://aes-256-gcm:pw@[::1]:8388#v6", "aes-256-gcm", "pw", "::1", 8388)
}

// Tag with raw (unencoded) spaces and unicode — Telegram copy-paste reality.
func TestSweepSSTagRawSpacesUnicode(t *testing.T) {
	_, tag := zzSSParse(t, "ss://aes-256-gcm:pw@1.2.3.4:8388#My Server 🚀 RU")
	if !strings.HasPrefix(tag, "My Server 🚀 RU") {
		t.Errorf("raw-space/unicode tag mangled: %q", tag)
	}
}

// ---------------------------------------------------------------------------
// F. shadowtls:// (NekoBox-style export)
// ---------------------------------------------------------------------------

// Bare-userinfo password containing ':' — url.Parse splits userinfo at the
// first ':', shadowtls.go:53 then keeps only the part AFTER it, silently
// truncating the real password.
func TestSweepShadowTLSPasswordWithColon(t *testing.T) {
	out, err := ray2sing.ShadowTLSSingbox("shadowtls://pa%3Ass@1.2.3.4:443?version=3&sni=gateway.icloud.com#n")
	if err != nil {
		t.Fatalf("ShadowTLSSingbox error: %v", err)
	}
	opts := out.Options.(*option.ShadowTLSOutboundOptions)
	if opts.Password != "pa:ss" {
		t.Errorf("percent-encoded ':' password mangled: %q", opts.Password)
	}
}

// ---------------------------------------------------------------------------
// G. ssconf:// / beepass (Outline dynamic access keys)
// ---------------------------------------------------------------------------

func zzBeepass(t *testing.T, body string) (*option.Outbound, error) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	old := ray2sing.SSConfHTTPClient
	ray2sing.SSConfHTTPClient = srv.Client()
	defer func() { ray2sing.SSConfHTTPClient = old }()
	return ray2sing.BeepassSingbox("ssconf://" + u.Host + "/conf#BeePass")
}

// beepass.go:93 skips the ssSupportedMethods gate that ShadowsocksSingbox has,
// so an unsupported cipher from a dynamic key sails through and dies as an
// invalid stub ("unknown method") at outbound creation — exactly the failure
// mode the gate exists to prevent.
func TestSweepBeepassUnsupportedCipherRejectedReadably(t *testing.T) {
	out, err := zzBeepass(t, `{"server":"1.2.3.4","server_port":8388,"password":"pw","method":"chacha8-ietf-poly1305"}`)
	if err == nil {
		so := out.Options.(*option.ShadowsocksOutboundOptions)
		t.Fatalf("unsupported cipher passed through silently (method=%q) — becomes an invalid stub at outbound creation", so.Method)
	}
	if !strings.Contains(err.Error(), "chacha8-ietf-poly1305") {
		t.Errorf("error does not name the cipher: %v", err)
	}
}

// An ssconf endpoint answering with a SIP008 server-list document (instead of
// the single-object Outline shape) unmarshals into beepassData with ALL fields
// empty — beepass.go:77 only falls back to the ss:// path on unmarshal ERROR,
// so a structurally-valid-but-different JSON yields a silent garbage node
// (server "", port 443, method "").
func TestSweepBeepassSIP008ListBodyNotSilentGarbage(t *testing.T) {
	body := `{"version":1,"servers":[{"server":"9.9.9.9","server_port":8388,"method":"aes-256-gcm","password":"pw","remarks":"r"}]}`
	out, err := zzBeepass(t, body)
	if err != nil {
		return // a readable error is acceptable behavior
	}
	so := out.Options.(*option.ShadowsocksOutboundOptions)
	if so.Server == "" || so.Method == "" {
		t.Fatalf("SIP008-list ssconf body produced a silent garbage node: server=%q method=%q port=%d",
			so.Server, so.Method, so.ServerPort)
	}
}

// ssconf endpoint answering with a raw ss:// URI (documented Outline variant)
// must go through the ShadowsocksSingbox fallback.
func TestSweepBeepassRawSSURIFallback(t *testing.T) {
	out, err := zzBeepass(t, "ss://"+zzStdB64("aes-256-gcm:pw@5.6.7.8:8389")+"#dyn")
	if err != nil {
		t.Fatalf("raw ss:// ssconf body error: %v", err)
	}
	so := out.Options.(*option.ShadowsocksOutboundOptions)
	if so.Server != "5.6.7.8" || so.Method != "aes-256-gcm" || so.Password != "pw" || so.ServerPort != 8389 {
		t.Errorf("raw ss:// fallback mangled: %+v", so)
	}
}

// ---------------------------------------------------------------------------
// H. SIP008 JSON subscription document (full field set)
// ---------------------------------------------------------------------------

// plugin + plugin_opts + unicode remarks + string server_port must survive the
// SIP008 -> ss:// -> outbound round trip.
func TestSweepSIP008FullFieldSet(t *testing.T) {
	doc := `{"version":1,"servers":[{` +
		`"server":"7.7.7.7","server_port":"4433","method":"aes-256-gcm","password":"p@ss:w/rd",` +
		`"plugin":"v2ray-plugin","plugin_opts":"tls;host=cdn.example.com","remarks":"Токио 🇯🇵"}]}`
	opts, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), doc, false)
	if err != nil {
		t.Fatalf("SIP008 parse failed: %v", err)
	}
	if len(opts.Outbounds) == 0 {
		t.Fatal("no outbounds from SIP008 doc")
	}
	o := opts.Outbounds[0]
	so := o.Options.(*option.ShadowsocksOutboundOptions)
	if so.Server != "7.7.7.7" || so.ServerPort != 4433 {
		t.Errorf("server/port mangled: %s:%d", so.Server, so.ServerPort)
	}
	if so.Method != "aes-256-gcm" || so.Password != "p@ss:w/rd" {
		t.Errorf("method/password mangled: %q / %q", so.Method, so.Password)
	}
	if so.Plugin != "v2ray-plugin" || so.PluginOptions != "tls;host=cdn.example.com" {
		t.Errorf("plugin/plugin_opts mangled: %q / %q", so.Plugin, so.PluginOptions)
	}
	if !strings.HasPrefix(o.Tag, "Токио 🇯🇵") {
		t.Errorf("unicode remarks mangled: %q", o.Tag)
	}
}
