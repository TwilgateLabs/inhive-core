package ray2sing_test

// convert_sharelinks_test.go — the acceptance guard for ConvertToShareLinks and
// the extended singbox_ingest reverse coverage (Task A + B, 2026-07-23).
//
// Two properties per added type:
//  1. CANONICALIZATION — ConvertToShareLinks(singbox-JSON) emits a canonical
//     share-link URI (not the JSON fallback) with the query-param spelling BOTH
//     ray2sing and the Dart protocol registry understand.
//  2. FAITHFUL ROUND-TRIP — feeding that URI back through the full pipeline
//     rebuilds the same node's semantic fields (this is the compat_corpus bar:
//     "semantically == the JSON", not "it parsed").
//
// Plus the universal-client guarantee: a type we cannot canonicalize
// (olcrtc/ssh/utproto) is NEVER dropped — it degrades to minified node JSON,
// input order preserved.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/twilgate/xray2sing/ray2sing"
)

func contextBG() context.Context { return context.Background() }

func base64Std(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// records splits a ConvertToShareLinks result into per-server lines.
func records(t *testing.T, content string) []string {
	t.Helper()
	out, err := ray2sing.ConvertToShareLinks(content)
	if err != nil {
		t.Fatalf("ConvertToShareLinks(%.60q) error: %v", content, err)
	}
	return strings.Split(out, "\n")
}

// oneRecord asserts ConvertToShareLinks produced exactly one record and returns it.
func oneRecord(t *testing.T, content string) string {
	t.Helper()
	r := records(t, content)
	if len(r) != 1 {
		t.Fatalf("want exactly 1 record, got %d: %v", len(r), r)
	}
	return r[0]
}

// firstEndpoint parses a config through the full pipeline and returns its first
// endpoint (wireguard/awg live in the "endpoints" array, not "outbounds").
func firstEndpoint(t *testing.T, config string) map[string]any {
	t.Helper()
	out, err := ray2sing.Ray2Singbox(contextBG(), config, false)
	if err != nil {
		t.Fatalf("parse error for %.80q: %v", config, err)
	}
	var doc struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal produced config: %v\n%s", err, out)
	}
	if len(doc.Endpoints) == 0 {
		t.Fatalf("no endpoints produced for: %.120q\n%s", config, out)
	}
	return doc.Endpoints[0]
}

// --- wireguard / awg endpoints --------------------------------------------

func TestConvert_WireGuardEndpoint_RoundTrip(t *testing.T) {
	// Keys deliberately carry literal '+' and '/' (the base64 alphabet) to guard
	// the classic query '+'→space trap: a WireGuard key must survive verbatim.
	cfg := `{"endpoints":[{"type":"wireguard","tag":"wg-node","private_key":"kL9x+Yz3/AbC7dEf+GhI2jKl/MnOp4=","address":"10.13.13.2/32","mtu":1420,` +
		`"peers":[{"address":"vpn.example.com","port":51820,"public_key":"Pub+Key/With+Slash2jKlMnOpQrStUv=","pre_shared_key":"pS+k/eY2==","allowed_ips":["0.0.0.0/0","::/0"],"persistent_keepalive_interval":25,"reserved":[1,2,3]}]}]}`

	rec := oneRecord(t, cfg)
	if !strings.HasPrefix(rec, "wireguard://") {
		t.Fatalf("want a wireguard:// canonical URI, got: %s", rec)
	}
	// Param spelling both ray2sing (AWGSingbox) and Dart (_buildWireguard) read.
	for _, key := range []string{"privatekey=", "peerpublickey=", "presharedkey=", "address=", "allowedips=", "keepalive=", "reserved=", "mtu="} {
		if !strings.Contains(rec, key) {
			t.Errorf("URI missing %q: %s", key, rec)
		}
	}

	ep := firstEndpoint(t, rec)
	if ep["type"] != "wireguard" {
		t.Fatalf("endpoint type = %v, want wireguard", ep["type"])
	}
	if ep["private_key"] != "kL9x+Yz3/AbC7dEf+GhI2jKl/MnOp4=" {
		t.Errorf("private_key = %v (base64 with literal '+'/'/' must survive verbatim)", ep["private_key"])
	}
	if a := asStrings(ep["address"]); !eqStrings(a, []string{"10.13.13.2/32"}) {
		t.Errorf("address = %v, want [10.13.13.2/32]", ep["address"])
	}
	peers, _ := ep["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("peers = %v, want exactly 1", ep["peers"])
	}
	p := peers[0].(map[string]any)
	if p["address"] != "vpn.example.com" || p["port"] != float64(51820) {
		t.Errorf("peer endpoint = %v:%v, want vpn.example.com:51820", p["address"], p["port"])
	}
	if p["public_key"] != "Pub+Key/With+Slash2jKlMnOpQrStUv=" {
		t.Errorf("peer public_key = %v (base64 with '+'/'/' must survive)", p["public_key"])
	}
	if p["pre_shared_key"] != "pS+k/eY2==" {
		t.Errorf("peer pre_shared_key = %v", p["pre_shared_key"])
	}
	if p["persistent_keepalive_interval"] != float64(25) {
		t.Errorf("keepalive = %v, want 25", p["persistent_keepalive_interval"])
	}
	// sing-box marshals []uint8 reserved as a base64 string: [1,2,3] -> "AQID".
	if p["reserved"] != "AQID" {
		t.Errorf("reserved = %v, want base64 AQID (=[1 2 3])", p["reserved"])
	}
	if !eqStrings(asStrings(p["allowed_ips"]), []string{"0.0.0.0/0", "::/0"}) {
		t.Errorf("allowed_ips = %v, want [0.0.0.0/0 ::/0]", p["allowed_ips"])
	}
}

func TestConvert_AWGEndpoint_RoundTrip(t *testing.T) {
	cfg := `{"endpoints":[{"type":"awg","tag":"awg-node","private_key":"cHJpdmF0ZStrZXk=","address":"10.13.13.2/32",` +
		`"jc":4,"jmin":8,"jmax":80,"s1":15,"s2":20,"h1":"1234567890","h2":"1234567891","h3":"1234567892","h4":"1234567893",` +
		`"peers":[{"address":"1.2.3.4","port":51820,"public_key":"cGVlcitwdWI=","allowed_ips":["0.0.0.0/0"]}]}]}`

	rec := oneRecord(t, cfg)
	if !strings.HasPrefix(rec, "awg://") {
		t.Fatalf("want an awg:// canonical URI (AmneziaWG obfs present), got: %s", rec)
	}
	for _, key := range []string{"jc=4", "jmin=8", "jmax=80", "s1=15", "s2=20", "h1=1234567890", "h4=1234567893"} {
		if !strings.Contains(rec, key) {
			t.Errorf("URI missing %q: %s", key, rec)
		}
	}
	ep := firstEndpoint(t, rec)
	if ep["type"] != "awg" {
		t.Fatalf("endpoint type = %v, want awg", ep["type"])
	}
	if ep["jc"] != float64(4) || ep["jmax"] != float64(80) || ep["h1"] != "1234567890" {
		t.Errorf("awg obfs params lost: jc=%v jmax=%v h1=%v", ep["jc"], ep["jmax"], ep["h1"])
	}
}

// Multi-peer / noise endpoints have no single-URI form → JSON fallback, never lost.
func TestConvert_WireGuardMultiPeer_Fallback(t *testing.T) {
	cfg := `{"endpoints":[{"type":"wireguard","tag":"multi","private_key":"cGsx","address":"10.0.0.2/32",` +
		`"peers":[{"address":"a.example.com","port":51820,"public_key":"cHViMQ=="},{"address":"b.example.com","port":51821,"public_key":"cHViMg=="}]}]}`
	rec := oneRecord(t, cfg)
	if strings.HasPrefix(rec, "wireguard://") || strings.HasPrefix(rec, "awg://") {
		t.Fatalf("multi-peer endpoint must degrade to JSON, not a lossy single-peer URI: %s", rec)
	}
	if !strings.HasPrefix(rec, "{") || !strings.Contains(rec, `"type":"wireguard"`) {
		t.Errorf("fallback must be the preserved endpoint JSON, got: %s", rec)
	}
}

// --- dnstt / psiphon (server-less) -----------------------------------------

func TestConvert_Dnstt_RoundTrip(t *testing.T) {
	cfg := `{"outbounds":[{"type":"dnstt","tag":"dt","domain":"t.example.com","pubkey":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","resolver":"1.1.1.1:53"}]}`
	rec := oneRecord(t, cfg)
	if !strings.HasPrefix(rec, "dnstt://t.example.com?") {
		t.Fatalf("want dnstt://t.example.com?..., got: %s", rec)
	}
	if !strings.Contains(rec, "pubkey=") || !strings.Contains(rec, "resolver=") {
		t.Errorf("dnstt URI missing pubkey/resolver: %s", rec)
	}
	ob := mustOutbound(t, rec)
	if ob["type"] != "dnstt" || ob["domain"] != "t.example.com" {
		t.Errorf("dnstt round-trip = %v/%v", ob["type"], ob["domain"])
	}
	if !strings.HasPrefix(ob["pubkey"].(string), "0123456789abcdef") || ob["resolver"] != "1.1.1.1:53" {
		t.Errorf("dnstt pubkey/resolver lost: %v / %v", ob["pubkey"], ob["resolver"])
	}
}

func TestConvert_Psiphon_RoundTrip(t *testing.T) {
	cfg := `{"outbounds":[{"type":"psiphon","tag":"psi","egress_region":"NL","remote_server_list_url":"https://example.com/list","remote_server_list_signature_public_key":"SIGKEY"}]}`
	rec := oneRecord(t, cfg)
	if !strings.HasPrefix(rec, "psiphon://") {
		t.Fatalf("want psiphon:// URI, got: %s", rec)
	}
	if !strings.Contains(rec, "region=NL") {
		t.Errorf("psiphon URI missing region=NL: %s", rec)
	}
	ob := mustOutbound(t, rec)
	if ob["type"] != "psiphon" || ob["egress_region"] != "NL" {
		t.Errorf("psiphon round-trip = %v/%v", ob["type"], ob["egress_region"])
	}
	if ob["remote_server_list_url"] != "https://example.com/list" || ob["remote_server_list_signature_public_key"] != "SIGKEY" {
		t.Errorf("psiphon server-list fields lost: %v", ob)
	}
}

// --- mieru / naive ---------------------------------------------------------

func TestConvert_Mieru_RoundTrip(t *testing.T) {
	cfg := `{"outbounds":[{"type":"mieru","tag":"mi","server":"1.2.3.4","username":"baozi","password":"manlianpenfen","multiplexing":"MULTIPLEXING_HIGH","handshake_mode":"HANDSHAKE_NO_WAIT","mtu":1400,"portBindings":[{"protocol":"TCP","port":6666},{"protocol":"UDP","portRange":"9998-9999"}]}]}`
	rec := oneRecord(t, cfg)
	if !strings.HasPrefix(rec, "mieru://") {
		t.Fatalf("want mieru:// URI, got: %s", rec)
	}
	ob := mustOutbound(t, rec)
	if ob["type"] != "mieru" || ob["server"] != "1.2.3.4" {
		t.Errorf("mieru server = %v/%v", ob["type"], ob["server"])
	}
	if ob["username"] != "baozi" || ob["password"] != "manlianpenfen" {
		t.Errorf("mieru creds lost: %v / %v", ob["username"], ob["password"])
	}
	if ob["multiplexing"] != "MULTIPLEXING_HIGH" || ob["handshake_mode"] != "HANDSHAKE_NO_WAIT" {
		t.Errorf("mieru mux/handshake lost: %v / %v", ob["multiplexing"], ob["handshake_mode"])
	}
	pb, _ := ob["portBindings"].([]any)
	if len(pb) != 2 {
		t.Fatalf("mieru portBindings = %v, want 2", ob["portBindings"])
	}
	b0 := pb[0].(map[string]any)
	if b0["protocol"] != "TCP" || b0["port"] != float64(6666) {
		t.Errorf("binding[0] = %v, want {TCP,6666}", b0)
	}
	b1 := pb[1].(map[string]any)
	if b1["protocol"] != "UDP" || b1["portRange"] != "9998-9999" {
		t.Errorf("binding[1] = %v, want {UDP,9998-9999}", b1)
	}
}

func TestConvert_Naive_RoundTrip(t *testing.T) {
	cfg := `{"outbounds":[{"type":"naive","tag":"nv","server":"proxy.example.com","server_port":443,"username":"user","password":"pass","tls":{"enabled":true,"server_name":"proxy.example.com","utls":{"enabled":true,"fingerprint":"chrome"}}}]}`
	rec := oneRecord(t, cfg)
	if !strings.HasPrefix(rec, "naive+https://") {
		t.Fatalf("want naive+https:// URI, got: %s", rec)
	}
	ob := mustOutbound(t, rec)
	if ob["type"] != "naive" || ob["server"] != "proxy.example.com" || ob["server_port"] != float64(443) {
		t.Errorf("naive endpoint = %v %v:%v", ob["type"], ob["server"], ob["server_port"])
	}
	if ob["username"] != "user" || ob["password"] != "pass" {
		t.Errorf("naive creds lost: %v / %v", ob["username"], ob["password"])
	}
	if tls := sub(ob, "tls"); tls == nil || tls["server_name"] != "proxy.example.com" {
		t.Errorf("naive tls.server_name lost: %v", ob["tls"])
	}
}

// naive carrying a field the reverse cannot express (insecure) → JSON fallback.
func TestConvert_Naive_InsecureFallback(t *testing.T) {
	cfg := `{"outbounds":[{"type":"naive","tag":"nv","server":"p.example.com","server_port":443,"username":"u","password":"p","tls":{"enabled":true,"server_name":"p.example.com","insecure":true}}]}`
	rec := oneRecord(t, cfg)
	if strings.HasPrefix(rec, "naive") {
		t.Fatalf("naive+insecure has no faithful share-link → must fall back to JSON, got: %s", rec)
	}
	if !strings.HasPrefix(rec, "{") || !strings.Contains(rec, `"type":"naive"`) {
		t.Errorf("fallback must preserve the naive node as JSON, got: %s", rec)
	}
}

// --- universal-client: never lose a server ---------------------------------

// olcrtc/ssh/utproto have no faithful JSON→URI path — they must be preserved as
// minified node JSON, in input order, alongside canonicalized siblings.
func TestConvert_Fallback_PreservesUncoveredTypes(t *testing.T) {
	u := corpusUUID
	cfg := `{"outbounds":[` +
		`{"type":"vless","tag":"a","server":"a.example.com","server_port":443,"uuid":"` + u + `","tls":{"enabled":true,"server_name":"a.example.com"}},` +
		`{"type":"olcrtc","tag":"b","server":"b.example.com","server_port":443,"room":"r1"},` +
		`{"type":"ssh","tag":"c","server":"c.example.com","server_port":22,"user":"root","password":"pw"},` +
		`{"type":"selector","tag":"sel","outbounds":["a","b"]},` +
		`{"type":"utproto","tag":"d","server":"d.example.com","server_port":8443,"secret":"deadbeef","tls_domain":"learn.microsoft.com"}` +
		`]}`
	recs := records(t, cfg)
	// vless canonicalizes; olcrtc/ssh/utproto fall back to JSON; selector dropped.
	if len(recs) != 4 {
		t.Fatalf("want 4 records (vless + 3 fallbacks, selector dropped), got %d: %v", len(recs), recs)
	}
	if !strings.HasPrefix(recs[0], "vless://") {
		t.Errorf("record[0] should be canonical vless://, got: %s", recs[0])
	}
	// Order preserved and each uncovered node preserved as JSON.
	if !strings.Contains(recs[1], `"type":"olcrtc"`) || !strings.HasPrefix(recs[1], "{") {
		t.Errorf("record[1] should be olcrtc JSON fallback, got: %s", recs[1])
	}
	if !strings.Contains(recs[2], `"type":"ssh"`) {
		t.Errorf("record[2] should be ssh JSON fallback, got: %s", recs[2])
	}
	if !strings.Contains(recs[3], `"type":"utproto"`) {
		t.Errorf("record[3] should be utproto JSON fallback, got: %s", recs[3])
	}
	// Fallback JSON is minified (single line, no indentation).
	for i, r := range recs {
		if strings.Contains(r, "\n") || strings.Contains(r, "\t") {
			t.Errorf("record[%d] must be single-line minified: %s", i, r)
		}
	}
}

// A fallback record must never leak the internal " § N" positional tag suffix.
func TestConvert_Fallback_StripsPipelineTagSuffix(t *testing.T) {
	cfg := `{"outbounds":[{"type":"ssh","tag":"my node § 7","server":"c.example.com","server_port":22,"user":"root","password":"pw"}]}`
	rec := oneRecord(t, cfg)
	var obj map[string]any
	if err := json.Unmarshal([]byte(rec), &obj); err != nil {
		t.Fatalf("fallback not valid JSON: %v (%s)", err, rec)
	}
	if obj["tag"] != "my node" {
		t.Errorf("tag = %v, want %q (the ' § N' uniquifier must be stripped)", obj["tag"], "my node")
	}
}

// --- share-link / base64 passthrough ---------------------------------------

func TestConvert_ShareLinkPassthrough(t *testing.T) {
	link := "vless://" + corpusUUID + "@h.example.com:443?type=ws&security=tls&sni=h.example.com&encryption=none#node"
	out, err := ray2sing.ConvertToShareLinks(link)
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if out != link {
		t.Errorf("a share-link is already canonical and must return as-is:\n got %q\nwant %q", out, link)
	}
}

func TestConvert_Base64ListPassthrough(t *testing.T) {
	a := "vless://" + corpusUUID + "@a.example.com:443?encryption=none&security=tls#a"
	b := "trojan://pw@b.example.com:443?security=tls#b"
	// A base64-wrapped newline list — the common subscription wire form.
	blob := base64Std(a + "\n" + b)
	recs := records(t, blob)
	if len(recs) != 2 || !strings.HasPrefix(recs[0], "vless://") || !strings.HasPrefix(recs[1], "trojan://") {
		t.Fatalf("base64 list must decode to 2 canonical share-links in order, got: %v", recs)
	}
}

func TestConvert_ErrorOnGarbage(t *testing.T) {
	if _, err := ray2sing.ConvertToShareLinks("this is not a subscription at all"); err == nil {
		t.Error("unrecognized body must be a hard error (mapped to __parse_error__ at the shim)")
	}
}
