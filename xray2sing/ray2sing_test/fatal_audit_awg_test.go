package ray2sing_test

// fatal_audit_awg_test.go — regression guards for the 2026-08 fatal-profile
// audit of the wg/awg/warp converters (findings group "awg"). Every case here
// used to pass the converter verbatim and then kill the WHOLE profile at
// Start (endpoint creation or IpcSet in the linked amneziawg-go v0.2.19), or
// silently mangle the value. The converter must instead fail the ONE link
// with an error naming the parameter, or clamp/drop with the documented
// semantics.

import (
	"strings"
	"testing"

	T "github.com/sagernet/sing-box/option"

	"github.com/twilgate/xray2sing/ray2sing"
)

// Valid 32-byte curve25519 keys (std base64). '+' and '/' are percent-encoded
// where they appear inside query values.
const (
	fatalPriv        = "NGC+MSAeaf7aoO7ouZl/XHwpmf2v5ZMlPNZUr0361xQ="
	fatalPrivEnc     = "NGC%2BMSAeaf7aoO7ouZl%2FXHwpmf2v5ZMlPNZUr0361xQ%3D"
	fatalPrivURLSafe = "NGC-MSAeaf7aoO7ouZl_XHwpmf2v5ZMlPNZUr0361xQ" // same key, url-safe, unpadded
	fatalPub         = "J6Cus/7pIy+K8iEfnuSRxbEL7LVWO/web5NCfsvI/ik="
	fatalPubEnc      = "J6Cus%2F7pIy%2BK8iEfnuSRxbEL7LVWO%2Fweb5NCfsvI%2Fik%3D"
)

func wgURL(extra string) string {
	return "wireguard://" + fatalPrivEnc + "@1.2.3.4:51820?publickey=" + fatalPubEnc + "&address=10.0.0.2/32" + extra
}

func awgURL(extra string) string {
	return "awg://" + fatalPrivEnc + "@1.2.3.4:51820?publickey=" + fatalPubEnc + "&address=10.0.0.2/32&jc=4&jmin=40&jmax=70" + extra
}

func awgOpts(t *testing.T, url string) *T.AwgEndpointOptions {
	t.Helper()
	ep, err := ray2sing.AWGSingbox(url)
	if err != nil {
		t.Fatalf("AWGSingbox(%q): %v", url, err)
	}
	opts, ok := ep.Options.(*T.AwgEndpointOptions)
	if !ok {
		t.Fatalf("endpoint type = %s (options %T), want awg", ep.Type, ep.Options)
	}
	return opts
}

func wgOpts(t *testing.T, url string) *T.WireGuardEndpointOptions {
	t.Helper()
	ep, err := ray2sing.AWGSingbox(url)
	if err != nil {
		t.Fatalf("AWGSingbox(%q): %v", url, err)
	}
	opts, ok := ep.Options.(*T.WireGuardEndpointOptions)
	if !ok {
		t.Fatalf("endpoint type = %s (options %T), want wireguard", ep.Type, ep.Options)
	}
	return opts
}

func wantErrNaming(t *testing.T, url, needle string) {
	t.Helper()
	_, err := ray2sing.AWGSingbox(url)
	if err == nil {
		t.Fatalf("AWGSingbox(%q): want an error naming %q, got nil", url, needle)
	}
	if !strings.Contains(err.Error(), needle) {
		t.Fatalf("AWGSingbox(%q): error %q does not name %q", url, err, needle)
	}
}

// --- Finding: I1-I5 passed verbatim; amneziawg-go v0.2.19 lacks AWG 1.5 tags ---

func TestAWG_ObfSpec_UnsupportedTagRejected(t *testing.T) {
	// <c> is an official AWG 1.5 tag but NOT in v0.2.19's obfBuilders
	// (device/obf.go: b,t,r,rc,rd,d,ds,dz) — it used to die inside IpcSet.
	wantErrNaming(t, awgURL("&i1=%3Cb%200xf6ab%3E%3Cc%3E"), "i1")
	// Malformed: missing enclosing '>'.
	wantErrNaming(t, awgURL("&i2=%3Cb%200xf6ab"), "i2")
	// Malformed: odd-length hex in <b>.
	wantErrNaming(t, awgURL("&i3=%3Cb%200xf6a%3E"), "i3")
}

func TestAWG_ObfSpec_SupportedTagsPass(t *testing.T) {
	opts := awgOpts(t, awgURL("&i1=%3Cb%200xf6ab%3E%3Ct%3E%3Cr%2016%3E"))
	if opts.I1 != "<b 0xf6ab><t><r 16>" {
		t.Fatalf("valid I1 spec mangled: %q", opts.I1)
	}
}

func TestAWG_ObfSpec_INIPathRejected(t *testing.T) {
	conf := "[Interface]\nPrivateKey = " + fatalPriv + "\nAddress = 10.8.0.2/32\nJc = 4\nJmin = 40\nJmax = 70\nI1 = <b 0xf6ab3267fa><c><t>\n" +
		"[Peer]\nPublicKey = " + fatalPub + "\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
	_, err := ray2sing.AWGSingboxTxt(conf)
	if err == nil || !strings.Contains(err.Error(), "I1") {
		t.Fatalf("INI with unsupported I1 tag: want error naming I1, got %v", err)
	}
}

// --- Finding: no base64 alphabet/length validation on wg/awg keys ---

func TestWG_Key_WrongLengthRejected(t *testing.T) {
	// "aGVsbG8=" is valid base64 but 5 bytes — used to pass creation and fail
	// FromHex's 32-byte check inside IpcSet at Start.
	wantErrNaming(t, "wireguard://"+fatalPrivEnc+"@1.2.3.4:51820?publickey=aGVsbG8%3D&address=10.0.0.2/32", "peer_public_key")
	wantErrNaming(t, "wireguard://aGVsbG8%3D@1.2.3.4:51820?publickey="+fatalPubEnc+"&address=10.0.0.2/32", "private_key")
	wantErrNaming(t, wgURL("&presharedkey=aGVsbG8%3D"), "preshared_key")
}

func TestWG_Key_URLSafeNormalized(t *testing.T) {
	// url-safe alphabet + missing padding used to fail base64.StdEncoding at
	// endpoint CREATION; now it must be re-encoded to the std alphabet.
	opts := wgOpts(t, "wireguard://"+fatalPrivURLSafe+"@1.2.3.4:51820?publickey="+fatalPubEnc+"&address=10.0.0.2/32")
	if opts.PrivateKey != fatalPriv {
		t.Fatalf("url-safe private key not normalized to std base64: %q", opts.PrivateKey)
	}
}

func TestWG_Key_StdKeySurvivesVerbatim(t *testing.T) {
	opts := wgOpts(t, wgURL(""))
	if opts.PrivateKey != fatalPriv || opts.Peers[0].PublicKey != fatalPub {
		t.Fatalf("std keys must survive verbatim: priv=%q pub=%q", opts.PrivateKey, opts.Peers[0].PublicKey)
	}
}

// --- Finding: INI [Peer] without PublicKey reached IpcSet with public_key="" ---

func TestAWGConf_PeerWithoutPublicKeyRejected(t *testing.T) {
	conf := "[Interface]\nPrivateKey = " + fatalPriv + "\nAddress = 10.8.0.2/32\n" +
		"[Peer]\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
	_, err := ray2sing.AWGSingboxTxt(conf)
	if err == nil || !strings.Contains(err.Error(), "PublicKey") {
		t.Fatalf("INI [Peer] without PublicKey: want 'missing peer PublicKey' error, got %v", err)
	}
}

// --- Finding: reserved= with count != 3 on the plain-WG path died at creation ---

func TestWG_Reserved_WrongCountRejected(t *testing.T) {
	wantErrNaming(t, wgURL("&reserved=12,52"), "reserved")
}

func TestWG_Reserved_SpacesTolerated(t *testing.T) {
	// The plain-WG loop used to skip TrimSpace (unlike the awg loop) so
	// "1, 2, 3" errored the link.
	opts := wgOpts(t, wgURL("&reserved=1,%202,%203"))
	if len(opts.Peers[0].Reserved) != 3 || opts.Peers[0].Reserved[2] != 3 {
		t.Fatalf("reserved '1, 2, 3' must parse to [1 2 3], got %v", opts.Peers[0].Reserved)
	}
}

func TestAWG_Reserved_WrongCountRejected(t *testing.T) {
	// The awg endpoint silently IGNORED a wrong count — equally wrong (WARP
	// routing silently broken); now a clear per-link error.
	wantErrNaming(t, awgURL("&reserved=12,52"), "reserved")
}

// --- Finding: workers=<negative> panicked sync.WaitGroup inside NewDevice at Start ---

func TestWG_Workers_NegativeDropped(t *testing.T) {
	opts := wgOpts(t, wgURL("&workers=-1"))
	if opts.Workers != 0 {
		t.Fatalf("workers=-1 must be dropped (0 -> NumCPU default), got %d", opts.Workers)
	}
	opts = wgOpts(t, wgURL("&workers=4"))
	if opts.Workers != 4 {
		t.Fatalf("workers=4 must survive, got %d", opts.Workers)
	}
}

// --- Finding: H1-H4 hex/overflow/junk failed newMagicHeader in IpcSet at Start ---

func TestAWG_MagicHeader_BadValuesRejected(t *testing.T) {
	wantErrNaming(t, awgURL("&h1=0xdeadbeef"), "h1") // hex not in v0.2.19 grammar
	wantErrNaming(t, awgURL("&h2=4294967296"), "h2") // > uint32
	wantErrNaming(t, awgURL("&h3=70-50"), "h3")      // reversed range
}

func TestAWG_MagicHeader_ValidValuesPass(t *testing.T) {
	opts := awgOpts(t, awgURL("&h1=1004746675&h2=50-70"))
	if opts.H1 != "1004746675" || opts.H2 != "50-70" {
		t.Fatalf("valid magic headers mangled: h1=%q h2=%q", opts.H1, opts.H2)
	}
}

// --- Finding: negative jc/jmin/jmax/s1-s4 failed amneziawg validation at Start ---

func TestAWG_NegativeJunkParamsClamped(t *testing.T) {
	opts := awgOpts(t, "awg://"+fatalPrivEnc+"@1.2.3.4:51820?publickey="+fatalPubEnc+"&address=10.0.0.2/32&jc=-1&jmin=40&jmax=70&s1=-5&s2=20")
	if opts.Jc != 0 || opts.S1 != 0 {
		t.Fatalf("negative jc/s1 must clamp to 0 (omitted), got jc=%d s1=%d", opts.Jc, opts.S1)
	}
	if opts.Jmin != 40 || opts.Jmax != 70 || opts.S2 != 20 {
		t.Fatalf("valid params must survive the clamp: jmin=%d jmax=%d s2=%d", opts.Jmin, opts.Jmax, opts.S2)
	}
}

func TestAWGConf_NegativeJunkParamsClamped(t *testing.T) {
	conf := "[Interface]\nPrivateKey = " + fatalPriv + "\nAddress = 10.8.0.2/32\nJc = -1\nJmin = 40\nJmax = 70\nS1 = -5\n" +
		"[Peer]\nPublicKey = " + fatalPub + "\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
	ep, err := ray2sing.AWGSingboxTxt(conf)
	if err != nil {
		t.Fatalf("AWGSingboxTxt: %v", err)
	}
	opts, ok := ep.Options.(*T.AwgEndpointOptions)
	if !ok {
		t.Fatalf("endpoint type = %s, want awg", ep.Type)
	}
	if opts.Jc != 0 || opts.S1 != 0 || opts.Jmin != 40 {
		t.Fatalf("INI negative Jc/S1 must clamp to 0: jc=%d s1=%d jmin=%d", opts.Jc, opts.S1, opts.Jmin)
	}
}

// --- Finding: mtu silent int->uint32 wrap on the plain-WG and WARP paths ---

func TestWG_MTU_NegativeIgnored(t *testing.T) {
	opts := wgOpts(t, wgURL("&mtu=-1"))
	if opts.MTU != 0 {
		t.Fatalf("mtu=-1 must be ignored (0 -> core default), got %d (the old uint32(toInt) wrap gave 4294967295)", opts.MTU)
	}
	opts = wgOpts(t, wgURL("&mtu=1420"))
	if opts.MTU != 1420 {
		t.Fatalf("mtu=1420 must survive, got %d", opts.MTU)
	}
}

func TestWARP_MTU_NegativeIgnored(t *testing.T) {
	ep, err := ray2sing.WarpSingbox("warp://user@engage.cloudflareclient.com:2408?mtu=-1")
	if err != nil {
		t.Fatalf("WarpSingbox: %v", err)
	}
	opts, ok := ep.Options.(*T.WireGuardWARPEndpointOptions)
	if !ok {
		t.Fatalf("options %T, want WARP", ep.Options)
	}
	if opts.MTU != 0 {
		t.Fatalf("warp mtu=-1 must be ignored, got %d", opts.MTU)
	}
}

func TestWARP_ProfileKeyValidated(t *testing.T) {
	_, err := ray2sing.WarpSingbox("warp://user@engage.cloudflareclient.com:2408?privatekey=aGVsbG8%3D")
	if err == nil || !strings.Contains(err.Error(), "privatekey") {
		t.Fatalf("warp with 5-byte privatekey: want error naming privatekey, got %v", err)
	}
}
