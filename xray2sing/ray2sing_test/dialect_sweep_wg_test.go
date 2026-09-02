package ray2sing_test

// zz_sweep_wg_test.go — 2026-09-02 sweep of the wireguard/AWG INI (.conf) and
// wg://-family URI surfaces against shapes real-world generators emit
// (wg(8)/wg-quick grammar, Cloudflare WARP generators, Amnezia exports).
//
// Reference grammar: wireguard-tools src/config.c — config_read_line strips
// ALL whitespace, then truncates the line at the first '#' (COMMENT_CHAR
// anywhere on the line, not only line-start); key_match() uses strncasecmp
// (keys are case-INsensitive); section headers compared with strcasecmp.
// Every conf that wg(8) accepts is fair game for a subscription/export.
//
// Failing tests here are CONFIRMED findings (parser rejects/mangles a
// grammar-valid shape); passing ones are guards for shapes verified to work.

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	T "github.com/sagernet/sing-box/option"

	"github.com/twilgate/xray2sing/ray2sing"
)

const (
	sweepPriv = "NGC+MSAeaf7aoO7ouZl/XHwpmf2v5ZMlPNZUr0361xQ="
	sweepPub  = "J6Cus/7pIy+K8iEfnuSRxbEL7LVWO/web5NCfsvI/ik="
)

// sweepEndpoints runs the full Parse pipeline and returns the endpoints.
func sweepEndpoints(t *testing.T, conf string) []T.Endpoint {
	t.Helper()
	opts, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), conf, false)
	if err != nil {
		t.Fatalf("Ray2SingboxOptions: %v\n--- input ---\n%s", err, conf)
	}
	return opts.Endpoints
}

func sweepOneWG(t *testing.T, conf string) *T.WireGuardEndpointOptions {
	t.Helper()
	eps := sweepEndpoints(t, conf)
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(eps))
	}
	o, ok := eps[0].Options.(*T.WireGuardEndpointOptions)
	if !ok {
		t.Fatalf("endpoint type = %s (options %T), want wireguard", eps[0].Type, eps[0].Options)
	}
	return o
}

func sweepOneAWG(t *testing.T, conf string) *T.AwgEndpointOptions {
	t.Helper()
	eps := sweepEndpoints(t, conf)
	if len(eps) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(eps))
	}
	o, ok := eps[0].Options.(*T.AwgEndpointOptions)
	if !ok {
		t.Fatalf("endpoint type = %s (options %T), want awg", eps[0].Type, eps[0].Options)
	}
	return o
}

// --- FINDING 1: trailing '#' comments corrupt values / kill the conf --------
//
// wg(8) truncates every line at the first '#' (config.c COMMENT_CHAR), so
// "PrivateKey = KEY # my key" is a fully valid wg-quick conf line; hand-edited
// and tutorial-derived confs carry these routinely ('#' can never appear
// inside base64/IP/port values, so truncation is always safe). AWGSingboxTxt
// only skips FULL-line comments (awg.go:221) — a trailing comment lands inside
// the value: PrivateKey fails base64 (whole conf rejected), Endpoint fails
// SplitHostPort (whole conf rejected), AllowedIPs fails prefix parse.

func TestSweepWG_INI_TrailingHashComments(t *testing.T) {
	conf := `[Interface]
PrivateKey = ` + sweepPriv + ` # client key
Address = 10.0.0.2/32

[Peer]
PublicKey = ` + sweepPub + `
AllowedIPs = 0.0.0.0/0 # route everything
Endpoint = 1.2.3.4:51820 # primary
PersistentKeepalive = 25 # nat
`
	o := sweepOneWG(t, conf)
	if o.PrivateKey != sweepPriv {
		t.Fatalf("private key corrupted by trailing comment: %q", o.PrivateKey)
	}
	if o.Peers[0].Address != "1.2.3.4" || o.Peers[0].Port != 51820 {
		t.Fatalf("endpoint corrupted by trailing comment: %v:%v", o.Peers[0].Address, o.Peers[0].Port)
	}
	if o.Peers[0].PersistentKeepaliveInterval != 25 {
		t.Fatalf("keepalive corrupted by trailing comment: %d", o.Peers[0].PersistentKeepaliveInterval)
	}
}

// --- FINDING 2: keys are matched case-SENSITIVELY ---------------------------
//
// wg(8) key_match() uses strncasecmp — "privatekey", "ADDRESS", "endpoint"
// are all valid. AWGSingboxTxt switches on the exact canonical spelling
// (awg.go:244+): non-canonical case is silently ignored → "missing
// PrivateKey" / "missing peer Endpoint" hard error, or (worse) lowercase
// jc/s1 silently drop the obfuscation and emit a plain-wireguard endpoint
// that can never handshake with the AWG server.

func TestSweepWG_INI_LowercaseKeys(t *testing.T) {
	conf := `[Interface]
privatekey = ` + sweepPriv + `
address = 10.0.0.2/32
jc = 4
jmin = 40
jmax = 70

[Peer]
publickey = ` + sweepPub + `
allowedips = 0.0.0.0/0
endpoint = 1.2.3.4:51820
`
	o := sweepOneAWG(t, conf)
	if o.PrivateKey != sweepPriv {
		t.Fatalf("lowercase privatekey not picked up: %q", o.PrivateKey)
	}
	if o.Jc != 4 || o.Jmin != 40 || o.Jmax != 70 {
		t.Fatalf("lowercase jc/jmin/jmax silently dropped: jc=%d jmin=%d jmax=%d", o.Jc, o.Jmin, o.Jmax)
	}
}

// --- FINDING 3 (Parse path): lowercase [interface] header not dispatched ----
//
// wg(8) compares section names with strcasecmp; ConvertToShareLinks already
// tolerates any case ((?i) regex in awgConfHeader) and AWGSingboxTxt itself
// lowercases sections — but the PARSE path dispatch is exact-case twice:
// splitByPrefix (spliter.go, prefix "[Interface]") and processSingleConfig's
// strings.HasPrefix (convert.go:154 over endpointParsers). A conf that
// converts fine via ConvertToShareLinks dies with "No outbounds found" via
// Ray2SingboxOptions. Asymmetric behavior between the two entry points.

func TestSweepWG_ParsePath_LowercaseSectionHeader(t *testing.T) {
	conf := `[interface]
PrivateKey = ` + sweepPriv + `
Address = 10.0.0.2/32

[peer]
PublicKey = ` + sweepPub + `
Endpoint = 1.2.3.4:51820
`
	o := sweepOneWG(t, conf)
	if o.PrivateKey != sweepPriv {
		t.Fatalf("private key: %q", o.PrivateKey)
	}
}

// --- FINDING 4 (Parse path): BOM immediately before [Interface] -------------
//
// Windows Notepad saves UTF-8 with a BOM; a .conf whose FIRST line is the
// [Interface] header (no leading comments — wgcf and warp generators emit
// exactly that) then starts "\uFEFF[Interface]". The Convert path strips the
// BOM (convertAWGConfEntries TrimPrefix); the Parse path does not —
// splitByPrefix's (?m)^ no longer sees the header at line start and
// processSingleConfig's HasPrefix fails → "No outbounds found".

func TestSweepWG_ParsePath_BOMBeforeInterface(t *testing.T) {
	conf := "\uFEFF[Interface]\nPrivateKey = " + sweepPriv + "\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = " + sweepPub + "\nEndpoint = 1.2.3.4:51820\n"
	o := sweepOneWG(t, conf)
	if o.PrivateKey != sweepPriv {
		t.Fatalf("private key: %q", o.PrivateKey)
	}
}

// --- FINDING 5: wg:// URI bare address= gets /24, not host prefix -----------
//
// The INI path was just fixed to give a bare Address the wg-quick host prefix
// (/32 v4, /128 v6). The URI path (AWGSingbox parsePrefixes, awg.go:532)
// still appends "/24" to any bare IP: a v2rayN/Streisand-style
// "wireguard://...?address=172.16.0.2" link gets 172.16.0.2/24, and a bare
// v6 WARP address becomes a nonsense ::/24 — silent mangle, same bug class
// as the .conf one, different entry point.

func TestSweepWG_URI_BareAddressHostPrefix(t *testing.T) {
	uri := "wireguard://NGC%2BMSAeaf7aoO7ouZl%2FXHwpmf2v5ZMlPNZUr0361xQ%3D@1.2.3.4:51820?publickey=J6Cus%2F7pIy%2BK8iEfnuSRxbEL7LVWO%2Fweb5NCfsvI%2Fik%3D&address=172.16.0.2,2606:4700:110:8949:fed8:2642:a640:8dcc"
	o := sweepOneWG(t, uri)
	if len(o.Address) != 2 {
		t.Fatalf("want 2 addresses, got %v", o.Address)
	}
	if got := o.Address[0].String(); got != "172.16.0.2/32" {
		t.Fatalf("bare v4 address must get /32 (wg-quick host semantics), got %s", got)
	}
	if got := o.Address[1].String(); got != "2606:4700:110:8949:fed8:2642:a640:8dcc/128" {
		t.Fatalf("bare v6 address must get /128, got %s", got)
	}
}

// --- Guards: shapes verified to work (keep passing) -------------------------

// CRLF line endings through the whole file (Windows exporters).
func TestSweepWG_INI_CRLF(t *testing.T) {
	conf := strings.ReplaceAll(`[Interface]
PrivateKey = `+sweepPriv+`
Address = 10.0.0.2/32
Jc = 4
Jmin = 40
Jmax = 70

[Peer]
PublicKey = `+sweepPub+`
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 1.2.3.4:51820
`, "\n", "\r\n")
	o := sweepOneAWG(t, conf)
	if o.PrivateKey != sweepPriv || o.Jc != 4 {
		t.Fatalf("CRLF conf mangled: key=%q jc=%d", o.PrivateKey, o.Jc)
	}
}

// wg-quick-only keys must be skipped, never rejected (Mullvad/Proton/wgcf
// exports carry DNS + MTU; server-side confs carry ListenPort/PostUp etc).
func TestSweepWG_INI_WgQuickOnlyKeysSkipped(t *testing.T) {
	conf := `[Interface]
PrivateKey = ` + sweepPriv + `
Address = 10.0.0.2/32
ListenPort = 51820
Table = off
FwMark = 0x8888
SaveConfig = true
DNS = 10.64.0.1, fc00::1
PreUp = echo up
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PreDown = echo predown
PostDown = iptables -D FORWARD -i %i -j ACCEPT
MTU = 1380

[Peer]
PublicKey = ` + sweepPub + `
AllowedIPs = 0.0.0.0/0
Endpoint = 1.2.3.4:51820
`
	o := sweepOneWG(t, conf)
	if o.MTU != 1380 {
		t.Fatalf("MTU = %d, want 1380", o.MTU)
	}
}

// Repeated Address / AllowedIPs keys append (wg(8) semantics).
func TestSweepWG_INI_RepeatedKeysAppend(t *testing.T) {
	conf := `[Interface]
PrivateKey = ` + sweepPriv + `
Address = 10.0.0.2/32
Address = fd00::2/128

[Peer]
PublicKey = ` + sweepPub + `
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = 1.2.3.4:51820
`
	o := sweepOneWG(t, conf)
	if len(o.Address) != 2 {
		t.Fatalf("repeated Address must append, got %v", o.Address)
	}
	if len(o.Peers[0].AllowedIPs) != 2 {
		t.Fatalf("repeated AllowedIPs must append, got %v", o.Peers[0].AllowedIPs)
	}
}

// Bracketed IPv6 Endpoint (WARP/Mullvad both publish v6 endpoints).
func TestSweepWG_INI_IPv6BracketEndpoint(t *testing.T) {
	conf := `[Interface]
PrivateKey = ` + sweepPriv + `
Address = 10.0.0.2/32

[Peer]
PublicKey = ` + sweepPub + `
Endpoint = [2606:4700:d0::a29f:c001]:2408
`
	o := sweepOneWG(t, conf)
	if o.Peers[0].Address != "2606:4700:d0::a29f:c001" || o.Peers[0].Port != 2408 {
		t.Fatalf("v6 endpoint mangled: %v:%v", o.Peers[0].Address, o.Peers[0].Port)
	}
}

// AWG 1.5 magic-header range form "start-end" in the INI must pass
// validateMagicHeader (explicitly requested verification).
func TestSweepWG_INI_MagicHeaderRange(t *testing.T) {
	conf := `[Interface]
PrivateKey = ` + sweepPriv + `
Address = 10.0.0.2/32
Jc = 4
Jmin = 40
Jmax = 70
H1 = 12345-67890
H2 = 5

[Peer]
PublicKey = ` + sweepPub + `
Endpoint = 1.2.3.4:51820
`
	o := sweepOneAWG(t, conf)
	if o.H1 != "12345-67890" || o.H2 != "5" {
		t.Fatalf("H range form mangled: h1=%q h2=%q", o.H1, o.H2)
	}
}
