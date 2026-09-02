package ray2sing_test

// Sweep v2 — vmess/vless/trojan real-world shape tolerance audit.
// Mission class: "real generators emit it, we reject/mangle it".
// FAILING subtests here are CONFIRMED findings (left failing on purpose,
// do NOT fix the parser in this wave); passing subtests are guards locking
// in shapes that already work.

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	T "github.com/sagernet/sing-box/option"
	"github.com/twilgate/xray2sing/ray2sing"
)

const sweepUUID = "d43ee5e3-1b07-56d7-b2ea-8d22c44fdc66"

func sweepB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// sweepParse1 runs the full converter on a single share link and returns the
// first produced outbound. A converter error == the node is LOST (finding).
func sweepParse1(t *testing.T, input string) *T.Outbound {
	t.Helper()
	opts, err := ray2sing.Ray2SingboxOptions(context.Background(), input, false)
	if err != nil {
		t.Fatalf("node LOST (converter error): %v\ninput: %s", err, input)
	}
	if opts == nil || len(opts.Outbounds) == 0 {
		t.Fatalf("node LOST (no outbounds)\ninput: %s", input)
	}
	return &opts.Outbounds[0]
}

func sweepVmess(t *testing.T, o *T.Outbound) *T.VMessOutboundOptions {
	t.Helper()
	v, ok := o.Options.(*T.VMessOutboundOptions)
	if !ok {
		t.Fatalf("outbound is %q (%T), want vmess", o.Type, o.Options)
	}
	return v
}

func sweepTrojan(t *testing.T, o *T.Outbound) *T.TrojanOutboundOptions {
	t.Helper()
	v, ok := o.Options.(*T.TrojanOutboundOptions)
	if !ok {
		t.Fatalf("outbound is %q (%T), want trojan", o.Type, o.Options)
	}
	return v
}

func sweepVless(t *testing.T, o *T.Outbound) *T.VLESSOutboundOptions {
	t.Helper()
	v, ok := o.Options.(*T.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("outbound is %q (%T), want vless", o.Type, o.Options)
	}
	return v
}

// ---------------------------------------------------------------------------
// VMESS — base64 JSON body tolerance
// ---------------------------------------------------------------------------

// v2rayN spec allows "port"/"aid"/"v" as JSON numbers OR strings; many panels
// emit numbers. "aid" and "v" absent entirely is emitted by minimal generators.
// GUARD: convertToStrings handles float64.
func TestSweepVmessJSONNumericPortAidAbsent(t *testing.T) {
	link := "vmess://" + sweepB64(`{"add":"1.2.3.4","port":8443,"id":"`+sweepUUID+`","net":"tcp","type":"none","ps":"n1"}`)
	v := sweepVmess(t, sweepParse1(t, link))
	if v.Server != "1.2.3.4" || v.ServerPort != 8443 {
		t.Fatalf("server/port mangled: %s:%d", v.Server, v.ServerPort)
	}
	if v.UUID != sweepUUID {
		t.Fatalf("uuid mangled: %q", v.UUID)
	}
	if v.Security != "auto" { // scy absent -> auto
		t.Fatalf("scy absent should default to auto, got %q", v.Security)
	}
}

// "ps" with emoji + unicode (every airport sub on earth). GUARD.
func TestSweepVmessJSONEmojiPS(t *testing.T) {
	link := "vmess://" + sweepB64(`{"add":"a.com","port":"443","id":"`+sweepUUID+`","net":"ws","path":"/x","tls":"tls","ps":"🇩🇪 Германия | ✈️ 0.5x"}`)
	o := sweepParse1(t, link)
	if !strings.Contains(o.Tag, "🇩🇪 Германия") {
		t.Fatalf("emoji ps lost from tag: %q", o.Tag)
	}
}

// "tls" as JSON bool true — seen in hand-rolled panel scripts (JSON bool
// instead of the v2rayN string "tls"). convertToStrings turns it into "true",
// getTLSOptions only matches the literal "tls"/"reality" => TLS silently
// DROPPED, node dies on a TLS-only server with no error. (silent-mangle class)
func TestSweepVmessJSONTLSBoolTrue(t *testing.T) {
	link := "vmess://" + sweepB64(`{"add":"a.com","port":443,"id":"`+sweepUUID+`","net":"ws","path":"/x","tls":true,"ps":"n"}`)
	v := sweepVmess(t, sweepParse1(t, link))
	if v.TLS == nil || !v.TLS.Enabled {
		t.Fatalf(`"tls":true (bool) must enable TLS; got TLS=%+v`, v.TLS)
	}
}

// "tls":"true" as string — same family, string spelling.
func TestSweepVmessJSONTLSStringTrue(t *testing.T) {
	link := "vmess://" + sweepB64(`{"add":"a.com","port":443,"id":"`+sweepUUID+`","net":"ws","path":"/x","tls":"true","ps":"n"}`)
	v := sweepVmess(t, sweepParse1(t, link))
	if v.TLS == nil || !v.TLS.Enabled {
		t.Fatalf(`"tls":"true" must enable TLS; got TLS=%+v`, v.TLS)
	}
}

// "tls":"none" / "tls":"false" mean DISABLED (Xray vocab). GUARD: must not
// accidentally enable TLS, and must not lose the node.
func TestSweepVmessJSONTLSNoneFalse(t *testing.T) {
	for _, val := range []string{`"none"`, `"false"`, `false`} {
		link := "vmess://" + sweepB64(`{"add":"1.2.3.4","port":80,"id":"`+sweepUUID+`","net":"tcp","type":"none","tls":`+val+`,"ps":"n"}`)
		v := sweepVmess(t, sweepParse1(t, link))
		if v.TLS != nil && v.TLS.Enabled {
			t.Fatalf("tls:%s must stay plaintext, got TLS enabled", val)
		}
	}
}

// "alpn" as JSON ARRAY (["h2","http/1.1"]) — emitted by JSON-native
// generators that mirror Xray streamSettings shape into the vmess blob.
// convertToStrings fmt.Sprintf's it into "[h2 http/1.1]" which then splits
// into a garbage single-element ALPN offered on the wire.
func TestSweepVmessJSONAlpnArray(t *testing.T) {
	link := "vmess://" + sweepB64(`{"add":"a.com","port":443,"id":"`+sweepUUID+`","net":"tcp","type":"none","tls":"tls","alpn":["h2","http/1.1"],"ps":"n"}`)
	v := sweepVmess(t, sweepParse1(t, link))
	if v.TLS == nil {
		t.Fatalf("TLS lost")
	}
	for _, a := range v.TLS.ALPN {
		if strings.ContainsAny(a, "[] ") {
			t.Fatalf("alpn array mangled into garbage ALPN %v", v.TLS.ALPN)
		}
	}
}

// Capitalized "Host" JSON key (PHP panel scripts). URL params are
// case-normalized in ParseUrl, but vmess JSON keys are used verbatim, so
// "Host" never reaches the ws Host header.
func TestSweepVmessJSONCapitalHostKey(t *testing.T) {
	link := "vmess://" + sweepB64(`{"add":"1.2.3.4","port":443,"id":"`+sweepUUID+`","net":"ws","path":"/x","Host":"cdn.example.com","tls":"tls","ps":"n"}`)
	v := sweepVmess(t, sweepParse1(t, link))
	if v.Transport == nil || v.Transport.Type != "ws" {
		t.Fatalf("ws transport lost: %+v", v.Transport)
	}
	hs := v.Transport.WebsocketOptions.Headers["Host"]
	if len(hs) == 0 || hs[0] != "cdn.example.com" {
		t.Fatalf(`"Host" (capitalized) key dropped; ws Host header = %v`, hs)
	}
}

// Extra unknown keys must be ignored, not fatal. GUARD.
func TestSweepVmessJSONUnknownKeys(t *testing.T) {
	link := "vmess://" + sweepB64(`{"add":"1.2.3.4","port":443,"id":"`+sweepUUID+`","net":"tcp","type":"none","ps":"n","fragment":"","testName":"x","group":"g","cc":123,"nested":{"a":1}}`)
	v := sweepVmess(t, sweepParse1(t, link))
	if v.Server != "1.2.3.4" {
		t.Fatalf("server mangled: %q", v.Server)
	}
}

// net=tcp + type=http + comma Host list (Xray tcp/http obfs host rotation,
// emitted by 3x-ui when "http伪装" is on). GUARD for the http-transport
// mapping + host list split.
func TestSweepVmessJSONTcpHTTPObfsHostList(t *testing.T) {
	link := "vmess://" + sweepB64(`{"add":"1.2.3.4","port":80,"id":"`+sweepUUID+`","net":"tcp","type":"http","host":"a.com,b.com","path":"/","ps":"n"}`)
	v := sweepVmess(t, sweepParse1(t, link))
	if v.Transport == nil || v.Transport.Type != "http" {
		t.Fatalf("tcp+http obfs must map to http transport, got %+v", v.Transport)
	}
	if len(v.Transport.HTTPOptions.Host) != 2 {
		t.Fatalf("host list mangled: %v", v.Transport.HTTPOptions.Host)
	}
}

// UUID with stray surrounding spaces (hand-edited subs, copy-paste). The
// value is passed verbatim; sing-box uuid.FromString then kills the node at
// outbound creation — after parse said OK. Low-frequency but silent-fail.
func TestSweepVmessJSONIDWithSpaces(t *testing.T) {
	link := "vmess://" + sweepB64(`{"add":"1.2.3.4","port":443,"id":" `+sweepUUID+` ","net":"tcp","type":"none","ps":"n"}`)
	v := sweepVmess(t, sweepParse1(t, link))
	if v.UUID != sweepUUID {
		t.Fatalf("uuid not trimmed: %q (will fail uuid.FromString at creation)", v.UUID)
	}
}

// Trailing comma in the JSON blob (sloppy panel template engines).
// encoding/json rejects it => whole node lost.
func TestSweepVmessJSONTrailingComma(t *testing.T) {
	link := "vmess://" + sweepB64(`{"add":"1.2.3.4","port":443,"id":"`+sweepUUID+`","net":"tcp","type":"none","ps":"n",}`)
	v := sweepVmess(t, sweepParse1(t, link))
	if v.Server != "1.2.3.4" {
		t.Fatalf("server mangled: %q", v.Server)
	}
}

// ---------------------------------------------------------------------------
// VMESS — non-JSON URI forms
// ---------------------------------------------------------------------------

// Shadowrocket export form: vmess://BASE64(method:uuid@host:port)?remarks=..&obfs=websocket&path=..&tls=1
// The body is NOT JSON; the query is NOT part of the base64. decodeVmess
// base64-decodes the whole thing (query included, which is not even valid
// base64) and json.Unmarshal's it => node lost.
func TestSweepVmessURIShadowrocket(t *testing.T) {
	link := "vmess://" + sweepB64("auto:"+sweepUUID+"@1.2.3.4:443") + "?remarks=SR%20node&obfs=websocket&obfsParam=cdn.example.com&path=/ws&tls=1"
	v := sweepVmess(t, sweepParse1(t, link))
	if v.Server != "1.2.3.4" || v.ServerPort != 443 || v.UUID != sweepUUID {
		t.Fatalf("shadowrocket vmess URI mangled: %s:%d uuid=%q", v.Server, v.ServerPort, v.UUID)
	}
}

// VMessAEAD plain-URI sharing form (v2fly VMessAEAD/VMessMD5 draft, emitted
// by Qv2ray / some panels): vmess://uuid@host:port?type=tcp&encryption=auto#name
// Not base64 at all => decodeBase64FaultTolerant errors => node lost.
func TestSweepVmessURIPlainAEAD(t *testing.T) {
	link := "vmess://" + sweepUUID + "@1.2.3.4:443?type=tcp&encryption=auto&security=tls&sni=a.com#aead"
	v := sweepVmess(t, sweepParse1(t, link))
	if v.Server != "1.2.3.4" || v.UUID != sweepUUID {
		t.Fatalf("VMessAEAD URI mangled: server=%q uuid=%q", v.Server, v.UUID)
	}
}

// ---------------------------------------------------------------------------
// VLESS — URI param tolerance
// ---------------------------------------------------------------------------

// Absolutely minimal vless link — no query at all (plain TCP reality-less
// nodes from 3x-ui "无加密" exports omit everything). GUARD.
func TestSweepVlessMinimalNoParams(t *testing.T) {
	v := sweepVless(t, sweepParse1(t, "vless://"+sweepUUID+"@1.2.3.4:8080#bare"))
	if v.Server != "1.2.3.4" || v.ServerPort != 8080 || v.UUID != sweepUUID {
		t.Fatalf("minimal vless mangled: %s:%d %q", v.Server, v.ServerPort, v.UUID)
	}
	if v.TLS != nil && v.TLS.Enabled {
		t.Fatalf("no security param must not enable TLS")
	}
}

// encryption= present-but-empty, flow= empty, headerType=none, sid= empty —
// the exact shape v2rayN emits for a reality node. GUARD.
func TestSweepVlessV2rayNRealityShape(t *testing.T) {
	link := "vless://" + sweepUUID + "@1.2.3.4:443?encryption=none&flow=&security=reality&sni=cdn.example.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=&spx=%2F&type=tcp&headerType=none#r"
	v := sweepVless(t, sweepParse1(t, link))
	if v.TLS == nil || v.TLS.Reality == nil || !v.TLS.Reality.Enabled {
		t.Fatalf("reality lost: %+v", v.TLS)
	}
	if v.TLS.Reality.ShortID != "" {
		t.Fatalf("empty sid must stay empty, got %q", v.TLS.Reality.ShortID)
	}
	if v.Flow != "" {
		t.Fatalf("empty flow= must map to no flow, got %q", v.Flow)
	}
}

// Port absent (vless://uuid@host?...) — some generators for 443-default
// nodes. GUARD: defaults to 443.
func TestSweepVlessNoPortDefaults443(t *testing.T) {
	v := sweepVless(t, sweepParse1(t, "vless://"+sweepUUID+"@example.com?security=tls&sni=example.com&type=ws&path=%2Fws#np"))
	if v.ServerPort != 443 {
		t.Fatalf("absent port must default to 443, got %d", v.ServerPort)
	}
}

// ---------------------------------------------------------------------------
// TROJAN
// ---------------------------------------------------------------------------

// Bare trojan link with NO query params — the original trojan-gfw/Igniter
// share form (trojan://password@host:port#name). Trojan is TLS BY DEFINITION;
// every other client (Xray, v2rayN, Shadowrocket, trojan-go) defaults
// security=tls when the param is absent. getTLSOptions sees neither tls= nor
// security= and returns TLS=nil => plaintext trojan that dies on handshake,
// silently.
func TestSweepTrojanBareDefaultsTLS(t *testing.T) {
	tr := sweepTrojan(t, sweepParse1(t, "trojan://s3cret@1.2.3.4:443#bare"))
	if tr.Password != "s3cret" || tr.Server != "1.2.3.4" {
		t.Fatalf("bare trojan mangled: %q@%s", tr.Password, tr.Server)
	}
	if tr.TLS == nil || !tr.TLS.Enabled {
		t.Fatalf("trojan without security= must default to TLS (trojan is always TLS); got TLS=%+v", tr.TLS)
	}
}

// Shadowrocket trojan links carry the SNI as peer= (its historical alias),
// often with allowInsecure=1. peer is read nowhere; SNI silently falls back
// to host/none and an SNI-routed server drops the handshake.
func TestSweepTrojanPeerAlias(t *testing.T) {
	tr := sweepTrojan(t, sweepParse1(t, "trojan://pw@1.2.3.4:443?security=tls&peer=sni.example.com&allowInsecure=1#sr"))
	if tr.TLS == nil || !tr.TLS.Enabled {
		t.Fatalf("TLS lost")
	}
	if tr.TLS.ServerName != "sni.example.com" {
		t.Fatalf("peer= alias dropped; server_name=%q", tr.TLS.ServerName)
	}
	if !tr.TLS.Insecure {
		t.Fatalf("allowInsecure=1 dropped")
	}
}

// trojan-go style link: sni= + type=ws + host= + path= (+ mux=). GUARD —
// and mux=? alone must NOT enable sing-mux (trojan-go smux is not sing-mux).
func TestSweepTrojanGoWsShape(t *testing.T) {
	tr := sweepTrojan(t, sweepParse1(t, "trojan://pw@t.example.com:443?sni=t.example.com&type=ws&host=cdn.example.com&path=%2Fws&mux=1&security=tls#tg"))
	if tr.Transport == nil || tr.Transport.Type != "ws" {
		t.Fatalf("ws transport lost: %+v", tr.Transport)
	}
	if tr.Multiplex != nil && tr.Multiplex.Enabled {
		t.Fatalf("trojan-go mux=1 must not enable sing-mux (incompatible wire protocols)")
	}
	if tr.TLS == nil || tr.TLS.ServerName != "t.example.com" {
		t.Fatalf("sni lost: %+v", tr.TLS)
	}
}

// Password with percent-encoded specials (v2rayN encodes; must decode). GUARD.
func TestSweepTrojanEncodedPassword(t *testing.T) {
	tr := sweepTrojan(t, sweepParse1(t, "trojan://p%40ss%3Aw0rd%21@1.2.3.4:443?security=tls&sni=a.com#enc"))
	if tr.Password != "p@ss:w0rd!" {
		t.Fatalf("percent-encoded password mangled: %q", tr.Password)
	}
}

// Password with a raw unencoded ':' (trojan-gfw treats whole userinfo as the
// password; sloppy generators don't encode). GUARD for the recombine fix.
func TestSweepTrojanRawColonPassword(t *testing.T) {
	tr := sweepTrojan(t, sweepParse1(t, "trojan://user:pass@1.2.3.4:443?security=tls&sni=a.com#col"))
	if tr.Password != "user:pass" {
		t.Fatalf("colon password truncated: %q", tr.Password)
	}
}
