package ray2sing

// amnezia_ingest_test.go — unit tests for the AmneziaVPN vpn:// ingestion.
//
// testdata/amnezia_config.vpn is a REAL export (single amnezia-xray container,
// vless+reality) — the live fixture the feature was built against. Hermetic:
// no network, everything else is synthesized in-process (hermetic-tests rule).

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// encodeAmneziaVPN builds a vpn:// link the same way amnezia-client does:
// base64url(no padding) over qCompress framing (4-byte BE size + zlib).
func encodeAmneziaVPN(t *testing.T, payload []byte) string {
	t.Helper()
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	buf.Write(hdr[:])
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(payload); err != nil {
		t.Fatalf("zlib write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zlib close: %v", err)
	}
	return "vpn://" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
}

// wrapContainers builds the top-level Amnezia export JSON.
func wrapContainers(t *testing.T, defaultContainer, description, hostName string, containers ...string) []byte {
	t.Helper()
	body := `{"containers":[` + strings.Join(containers, ",") + `],` +
		`"defaultContainer":"` + defaultContainer + `",` +
		`"description":"` + description + `",` +
		`"dns1":"1.1.1.1","dns2":"1.0.0.1",` +
		`"hostName":"` + hostName + `"}`
	if !json.Valid([]byte(body)) {
		t.Fatalf("test container JSON invalid: %s", body)
	}
	return []byte(body)
}

// minimal but real-shaped Xray last_config (vless+reality, Amnezia template).
const testXrayLastConfig = `{"inbounds":[{"listen":"127.0.0.1","port":10808,"protocol":"socks"}],` +
	`"log":{"loglevel":"error"},` +
	`"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"1.2.3.4","port":443,` +
	`"users":[{"id":"9d1a5bb6-0000-0000-0000-000000000000","flow":"xtls-rprx-vision","encryption":"none"}]}]},` +
	`"streamSettings":{"network":"tcp","security":"reality",` +
	`"realitySettings":{"fingerprint":"chrome","serverName":"cdn.example.com","publicKey":"pubkey123","shortId":"ab12","spiderX":""}}}]}`

func xrayContainer(t *testing.T) string {
	t.Helper()
	lc, _ := json.Marshal(testXrayLastConfig)
	return `{"container":"amnezia-xray","xray":{"last_config":` + string(lc) + `,"port":"443","transport_proto":"tcp"}}`
}

func ssContainer(t *testing.T) string {
	t.Helper()
	lc, _ := json.Marshal(`{"server":"5.6.7.8","server_port":"6789","local_port":"8585","password":"sspass","timeout":60,"method":"chacha20-ietf-poly1305"}`)
	return `{"container":"amnezia-shadowsocks","shadowsocks":{"last_config":` + string(lc) + `}}`
}

func openvpnContainer(t *testing.T) string {
	t.Helper()
	lc, _ := json.Marshal(`{"config":"client\ndev tun\n"}`)
	return `{"container":"amnezia-openvpn","openvpn":{"last_config":` + string(lc) + `}}`
}

const testAWGConf = `[Interface]
Address = 10.8.1.2/32
DNS = $PRIMARY_DNS, $SECONDARY_DNS
PrivateKey = cFRQb2ludHM9MTAuOC4xLjIvMzIgUHJpdmF0ZUtleT0K
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 68
H1 = 1234567890
H2 = 987654321
H3 = 1122334455
H4 = 5544332211
MTU = 1376

[Peer]
PublicKey = c2VydmVyUHViS2V5QmFzZTY0RW5jb2RlZEhlcmUwMDAK
PresharedKey = cHNrS2V5QmFzZTY0RW5jb2RlZFZhbHVlSGVyZTAwMDAK
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 9.8.7.6:51820
PersistentKeepalive = 25
`

func awgContainer(t *testing.T) string {
	t.Helper()
	lc, _ := json.Marshal(`{"config":` + string(mustJSON(t, testAWGConf)) + `,"hostName":"9.8.7.6","port":51820}`)
	return `{"container":"amnezia-awg","awg":{"last_config":` + string(lc) + `}}`
}

func mustJSON(t *testing.T, s string) []byte {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// --- the live fixture -------------------------------------------------------

func readFixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/amnezia_config.vpn")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(b)
}

func TestAmneziaFixtureIngest(t *testing.T) {
	uris, ok, err := ingestAmneziaVPN(readFixture(t))
	if err != nil || !ok {
		t.Fatalf("ingest failed: ok=%v err=%v", ok, err)
	}
	lines := strings.Split(uris, "\n")
	if len(lines) != 1 {
		t.Fatalf("want exactly 1 node, got %d: %q", len(lines), uris)
	}
	u := lines[0]
	for _, want := range []string{"vless://", "188.253.27.250", "security=reality", "flow=xtls-rprx-vision", "fp=chrome"} {
		if !strings.Contains(u, want) {
			t.Errorf("URI missing %q: %s", want, u)
		}
	}
	if !strings.HasSuffix(u, "#Osnova") {
		t.Errorf("node not named from description: %s", u)
	}
}

func TestAmneziaFixtureEndToEndParse(t *testing.T) {
	opts, err := GenerateConfigLite(readFixture(t), false)
	if err != nil {
		t.Fatalf("GenerateConfigLite: %v", err)
	}
	if len(opts.Outbounds) != 1 {
		t.Fatalf("want 1 outbound, got %d", len(opts.Outbounds))
	}
	ob := opts.Outbounds[0]
	if ob.Type != "vless" {
		t.Errorf("want vless outbound, got %s", ob.Type)
	}
	if !strings.HasPrefix(ob.Tag, "Osnova") {
		t.Errorf("tag should carry the Amnezia description, got %q", ob.Tag)
	}
}

func TestAmneziaFixtureConvertToShareLinks(t *testing.T) {
	out, err := ConvertToShareLinks(readFixture(t))
	if err != nil {
		t.Fatalf("ConvertToShareLinks: %v", err)
	}
	recs := strings.Split(out, "\n")
	if len(recs) != 1 || !strings.HasPrefix(recs[0], "vless://") {
		t.Fatalf("want 1 vless record, got: %q", out)
	}
	if !strings.HasSuffix(recs[0], "#Osnova") {
		t.Errorf("record not named from description: %s", recs[0])
	}
}

// --- synthetic containers ---------------------------------------------------

func TestAmneziaMultiContainerDefaultFirstAndSuffixes(t *testing.T) {
	// xray + shadowsocks + openvpn; default = shadowsocks. Expect: ss node
	// FIRST (defaultContainer), xray second, openvpn skipped without failing,
	// and names suffixed per protocol since >1 container converted.
	link := encodeAmneziaVPN(t, wrapContainers(t, "amnezia-shadowsocks", "Multi", "5.6.7.8",
		xrayContainer(t), ssContainer(t), openvpnContainer(t)))
	uris, ok, err := ingestAmneziaVPN(link)
	if err != nil || !ok {
		t.Fatalf("ingest failed: ok=%v err=%v", ok, err)
	}
	lines := strings.Split(uris, "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 nodes (ovpn skipped), got %d: %q", len(lines), uris)
	}
	if !strings.HasPrefix(lines[0], "ss://") {
		t.Errorf("defaultContainer node must come first, got: %s", lines[0])
	}
	if !strings.HasPrefix(lines[1], "vless://") {
		t.Errorf("second node should be the xray one, got: %s", lines[1])
	}
	if !strings.Contains(lines[0], "#Multi%20(Shadowsocks)") {
		t.Errorf("ss node missing protocol-suffixed name: %s", lines[0])
	}
	if !strings.Contains(lines[1], "#Multi%20(Xray)") {
		t.Errorf("xray node missing protocol-suffixed name: %s", lines[1])
	}
}

func TestAmneziaAWGContainer(t *testing.T) {
	link := encodeAmneziaVPN(t, wrapContainers(t, "amnezia-awg", "Junk", "9.8.7.6", awgContainer(t)))
	uris, ok, err := ingestAmneziaVPN(link)
	if err != nil || !ok {
		t.Fatalf("ingest failed: ok=%v err=%v", ok, err)
	}
	u := uris
	if !strings.HasPrefix(u, "awg://") {
		t.Fatalf("junk-parameterized tunnel must canonicalize as awg://, got: %s", u)
	}
	for _, want := range []string{"9.8.7.6:51820", "jc=4", "jmin=40", "jmax=70", "s1=15", "s2=68"} {
		if !strings.Contains(u, want) {
			t.Errorf("awg URI missing %q: %s", want, u)
		}
	}
	// End-to-end: the produced URI must parse into an endpoint.
	opts, err := GenerateConfigLite(link, false)
	if err != nil {
		t.Fatalf("GenerateConfigLite: %v", err)
	}
	if len(opts.Endpoints) != 1 {
		t.Fatalf("want 1 endpoint, got %d", len(opts.Endpoints))
	}
}

// --- honest refusals --------------------------------------------------------

func TestAmneziaOnlyUnsupportedContainerIsHardError(t *testing.T) {
	link := encodeAmneziaVPN(t, wrapContainers(t, "amnezia-openvpn", "OVPN", "1.1.1.1", openvpnContainer(t)))
	_, ok, err := ingestAmneziaVPN(link)
	if !ok {
		t.Fatal("a vpn:// body must be claimed (ok=true) even when refused")
	}
	if err == nil || !strings.Contains(err.Error(), "OpenVPN") {
		t.Fatalf("refusal must name the protocol, got: %v", err)
	}
	// Same via the public parse entrypoint — must NOT degrade into the generic
	// "No outbounds found".
	if _, gerr := GenerateConfigLite(link, false); gerr == nil || !strings.Contains(gerr.Error(), "OpenVPN") {
		t.Fatalf("parse path lost the refusal reason: %v", gerr)
	}
}

func TestAmneziaAPIKeyRejected(t *testing.T) {
	link := encodeAmneziaVPN(t, []byte(`{"config_version":1,"api_endpoint":"https://api.example","api_key":"k","protocol":"awg"}`))
	_, ok, err := ingestAmneziaVPN(link)
	if !ok || err == nil || !strings.Contains(err.Error(), "API key") {
		t.Fatalf("API-key payload must be rejected distinctly, got ok=%v err=%v", ok, err)
	}
}

// --- decode robustness ------------------------------------------------------

func TestAmneziaBrokenBase64(t *testing.T) {
	_, ok, err := ingestAmneziaVPN("vpn://!!!not-base64***")
	if !ok || err == nil || !strings.Contains(err.Error(), "base64") {
		t.Fatalf("want base64 error, got ok=%v err=%v", ok, err)
	}
}

func TestAmneziaBrokenZlib(t *testing.T) {
	data := []byte{0x00, 0x00, 0x00, 0x10, 0x78, 0xda, 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02}
	link := "vpn://" + base64.RawURLEncoding.EncodeToString(data)
	_, ok, err := ingestAmneziaVPN(link)
	if !ok || err == nil || !strings.Contains(err.Error(), "zlib") {
		t.Fatalf("want zlib error, got ok=%v err=%v", ok, err)
	}
}

func TestAmneziaLengthMismatch(t *testing.T) {
	payload := []byte(`{"containers":[]}`)
	var buf bytes.Buffer
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload))+7) // lie about the size
	buf.Write(hdr[:])
	zw := zlib.NewWriter(&buf)
	zw.Write(payload)
	zw.Close()
	link := "vpn://" + base64.RawURLEncoding.EncodeToString(buf.Bytes())
	_, ok, err := ingestAmneziaVPN(link)
	if !ok || err == nil || !strings.Contains(err.Error(), "size header") {
		t.Fatalf("want size-header mismatch error, got ok=%v err=%v", ok, err)
	}
}

func TestAmneziaPlainUncompressedPayload(t *testing.T) {
	// Legacy fallback: base64url of the raw JSON, no qCompress framing.
	payload := wrapContainers(t, "amnezia-xray", "Plain", "1.2.3.4", xrayContainer(t))
	link := "vpn://" + base64.RawURLEncoding.EncodeToString(payload)
	uris, ok, err := ingestAmneziaVPN(link)
	if err != nil || !ok {
		t.Fatalf("plain payload must import: ok=%v err=%v", ok, err)
	}
	if !strings.HasPrefix(uris, "vless://") {
		t.Fatalf("want vless node, got: %q", uris)
	}
}

func TestAmneziaWhitespaceAndPaddingTolerance(t *testing.T) {
	link := encodeAmneziaVPN(t, wrapContainers(t, "amnezia-xray", "Wrapped", "1.2.3.4", xrayContainer(t)))
	// Simulate messenger line-wrapping + added padding + surrounding blank lines.
	body := "\n  " + link[:40] + "\n" + link[40:] + "==\n"
	uris, ok, err := ingestAmneziaVPN(body)
	if err != nil || !ok || !strings.HasPrefix(uris, "vless://") {
		t.Fatalf("wrapped link must import: ok=%v err=%v uris=%q", ok, err, uris)
	}
}

func TestAmneziaNotAVPNLink(t *testing.T) {
	for _, body := range []string{"vless://x@y:443", "{\"outbounds\":[]}", "hello"} {
		if _, ok, err := ingestAmneziaVPN(body); ok || err != nil {
			t.Errorf("non-vpn body %q must fall through silently, got ok=%v err=%v", body, ok, err)
		}
	}
}

func TestAmneziaUnknownContainerListedInError(t *testing.T) {
	c := `{"container":"amnezia-quantum","quantum":{"last_config":"{}"}}`
	link := encodeAmneziaVPN(t, wrapContainers(t, "amnezia-quantum", "X", "1.1.1.1", c))
	_, ok, err := ingestAmneziaVPN(link)
	if !ok || err == nil || !strings.Contains(err.Error(), "amnezia-quantum") {
		t.Fatalf("unknown container must be named in the refusal, got ok=%v err=%v", ok, err)
	}
}
