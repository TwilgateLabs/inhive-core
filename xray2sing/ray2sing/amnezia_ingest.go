package ray2sing

// amnezia_ingest.go — AmneziaVPN `vpn://` container ingestion.
//
// Amnezia (amnezia-vpn/amnezia-client) shares self-hosted configs as
//
//	vpn://<base64url( qCompress(JSON) )>
//
// where qCompress is Qt's framing: a 4-byte BIG-ENDIAN uncompressed size
// followed by a raw zlib stream (0x78 ...). Older exports may carry the JSON
// uncompressed. The same payload also ships as a `.vpn` FILE ("Share for
// AmneziaVPN app"), so this ingest serves both the pasted link and file import
// (the app feeds file contents through the same text pipeline).
//
// The decoded JSON is a CONTAINER LIST:
//
//	{"containers":[{"container":"amnezia-xray","xray":{"last_config":"<...>"}}],
//	 "defaultContainer":"amnezia-xray",
//	 "description":"...", "hostName":"1.2.3.4", "dns1":"...", "dns2":"..."}
//
// Each container wraps ONE protocol config in a per-protocol sub-object whose
// key mirrors the container name ("amnezia-xray" -> "xray"). The interesting
// payload is always the "last_config" STRING: a full Xray client config for
// xray, a JSON with a wg-quick INI in "config" for wireguard/awg, an
// ss-libev-style JSON for shadowsocks.
//
// DESIGN — same contract as json_ingest.go: rebuild into the representations
// the EXISTING pipeline already owns and feed those back, never a second
// converter. xray last_config goes through ingestJSON/convertJSONEntries;
// wireguard/awg INI goes through convertAWGConfEntries (the same AWGSingboxTxt
// the [Interface] dispatcher uses); shadowsocks becomes a SIP002 ss:// URI via
// buildSSURI. Adding a future container type = ONE entry in amneziaHandlers.
//
// DELIBERATE DROPS (documented, not silent):
//   - top-level dns1/dns2 — InHive owns DNS centrally (anti-leak); same
//     rationale as the "outbounds only" scope of json_ingest.go.
//   - containers we cannot run yet (OpenVPN, OpenVPN-over-Cloak, IKEv2, SSTP)
//     are refused with ONE clear line naming the protocol — never a silent
//     zero-node import. They are planned protocols; when one lands, filling
//     `convert` in its amneziaHandlers entry is the whole wiring.
//
// hostName is only a naming fallback (description wins); the actual server
// address always comes from the per-protocol config itself.

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
)

// amneziaMaxUncompressed caps the qCompress declared size so a hostile link
// cannot balloon into a decompression bomb. Real Amnezia exports are a few KB.
const amneziaMaxUncompressed = 16 << 20 // 16 MiB

// looksLikeAmneziaVPN reports whether the body's first significant token is a
// vpn:// link (BOM/whitespace tolerated). Whole-body detection, mirroring the
// JSON/Clash container sniffs — a vpn:// link is a container, not a list entry.
func looksLikeAmneziaVPN(body string) bool {
	s := strings.TrimSpace(strings.TrimPrefix(body, "\uFEFF"))
	return len(s) > len("vpn://") && strings.EqualFold(s[:len("vpn://")], "vpn://")
}

// decodeAmneziaVPN unwraps vpn://<base64url(qCompress(JSON))> into the raw
// container JSON. Tolerant to: surrounding whitespace, line wrapping inside the
// base64 (copy-paste from chats), standard AND url-safe alphabets, missing
// padding. Hard-errors (never a silent fallthrough) on: broken base64, corrupt
// zlib, a qCompress length header that does not match the stream, implausible
// declared size.
func decodeAmneziaVPN(body string) ([]byte, error) {
	s := strings.TrimSpace(strings.TrimPrefix(body, "\uFEFF"))
	s = s[len("vpn://"):]
	// Strip ALL whitespace: messengers wrap long links.
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\n', '\r', '\t':
			continue
		}
		b.WriteRune(r)
	}
	payload := strings.TrimRight(b.String(), "=")

	// Amnezia emits Base64UrlEncoding | OmitTrailingEquals; accept the standard
	// alphabet too (some tooling re-encodes).
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		var stdErr error
		data, stdErr = base64.RawStdEncoding.DecodeString(payload)
		if stdErr != nil {
			return nil, E.New("Amnezia vpn:// link: payload is not valid base64: ", err)
		}
	}

	// qCompress framing: 4-byte big-endian uncompressed size + zlib stream.
	if len(data) >= 5 && data[4] == 0x78 {
		expected := binary.BigEndian.Uint32(data[:4])
		if expected == 0 || expected > amneziaMaxUncompressed {
			return nil, E.New("Amnezia vpn:// link: implausible uncompressed size in qCompress header")
		}
		zr, zerr := zlib.NewReader(bytes.NewReader(data[4:]))
		if zerr != nil {
			return nil, E.New("Amnezia vpn:// link: corrupt zlib stream: ", zerr)
		}
		defer zr.Close()
		out, rerr := io.ReadAll(io.LimitReader(zr, int64(expected)+1))
		if rerr != nil {
			return nil, E.New("Amnezia vpn:// link: corrupt zlib stream: ", rerr)
		}
		if len(out) != int(expected) {
			return nil, E.New("Amnezia vpn:// link: qCompress size header does not match the decompressed data")
		}
		return out, nil
	}

	// Legacy/uncompressed export: the payload is the JSON itself.
	if _, ok := looksLikeJSON(string(data)); ok {
		return data, nil
	}
	return nil, E.New("Amnezia vpn:// link: payload is neither qCompress(JSON) nor plain JSON")
}

// ---------------------------------------------------------------------------
// Container dispatch — the single point of extension.
// ---------------------------------------------------------------------------

// amneziaPartKind classifies what a converted container produced, so the two
// consumers (Parse and ConvertToShareLinks) can each route it through their
// OWN existing branch without this file growing a second converter.
type amneziaPartKind int

const (
	amneziaPartURI      amneziaPartKind = iota // body = ready share-link URI(s), newline-joined
	amneziaPartXrayJSON                        // body = full Xray client config JSON
	amneziaPartWGConf                          // body = wg-quick / AmneziaWG INI text
)

type amneziaPart struct {
	kind  amneziaPartKind
	body  string
	name  string // display name (description/hostName), "" = keep original tags
	label string // protocol label for multi-container name suffixes
}

// amneziaExport is the top-level decoded vpn:// JSON. dns1/dns2 are read only
// to make the drop explicit (see file header); the API-key fields are read to
// give the "this is not a server config" refusal a precise message. Amnezia's
// own detector (apiUtils::isServerFromApi, client 4.8.21.0) keys on
// config_version: 1 = Telegram-source key (api_endpoint/api_key/auth_data),
// 2 = Gateway key (api_config object) — both carry no "containers".
type amneziaExport struct {
	Containers       []json.RawMessage `json:"containers"`
	DefaultContainer string            `json:"defaultContainer"`
	Description      string            `json:"description"`
	HostName         string            `json:"hostName"`
	Dns1             string            `json:"dns1"`
	Dns2             string            `json:"dns2"`
	ConfigVersion    int               `json:"config_version"`
	APIEndpoint      string            `json:"api_endpoint"`
	APIKey           string            `json:"api_key"`
	AuthData         json.RawMessage   `json:"auth_data"`
	APIConfig        json.RawMessage   `json:"api_config"`
}

// isAPIKey reports whether the payload is an Amnezia Free/Premium API key
// rather than a self-hosted server config.
func (e *amneziaExport) isAPIKey() bool {
	return e.ConfigVersion != 0 || e.APIEndpoint != "" || e.APIKey != "" ||
		len(e.AuthData) > 0 || len(e.APIConfig) > 0
}

// amneziaHandler describes one container type. convert == nil means the
// container is RECOGNIZED but not convertible yet (planned protocol) — the
// import then refuses with a single line naming `label`, instead of importing
// zero nodes silently. Adding support for a container later = filling in
// `convert` on its map entry; nothing else changes.
type amneziaHandler struct {
	key     string // per-protocol sub-object key inside the container object
	label   string // human protocol name for messages and name suffixes
	convert func(sub json.RawMessage, top *amneziaExport) (amneziaPart, error)
}

// Container identifiers verified against amnezia-client 4.8.21.0
// (containers_defs.cpp containerToString): "amnezia-" + lowercase enum, except
// the special-cased Cloak -> "amnezia-openvpn-cloak" and Ipsec ->
// "amnezia-ipsec" (its protocol KEY is "ikev2" — containerTypeToString differs
// from containerToString). SSTP does not exist as a container.
//
// amnezia-shadowsocks (the "OpenVPN over Shadowsocks" container) converts via
// its ss sub-object: the ss-server in that container is a full, generic
// shadowsocks server, so the imported node works as a standalone proxy even
// though Amnezia itself chains OpenVPN through it. The Cloak container is NOT
// given the same treatment — its shadowsocks entry is plumbing for the
// ck-client chain, not an independently usable endpoint.
var amneziaHandlers = map[string]amneziaHandler{
	"amnezia-xray":          {key: "xray", label: "Xray", convert: amneziaXrayPart},
	"amnezia-ssxray":        {key: "ssxray", label: "Xray Shadowsocks", convert: amneziaXrayPart},
	"amnezia-wireguard":     {key: "wireguard", label: "WireGuard", convert: amneziaWGPart},
	"amnezia-awg":           {key: "awg", label: "AmneziaWG", convert: amneziaWGPart},
	"amnezia-awg2":          {key: "awg", label: "AmneziaWG 2", convert: amneziaWGPart},
	"amnezia-shadowsocks":   {key: "shadowsocks", label: "Shadowsocks", convert: amneziaSSPart},
	"amnezia-openvpn":       {key: "openvpn", label: "OpenVPN"},
	"amnezia-openvpn-cloak": {key: "cloak", label: "OpenVPN over Cloak"},
	"amnezia-ipsec":         {key: "ikev2", label: "IKEv2"},
}

// amneziaServiceContainers are non-VPN service containers (isShareable()==false
// in Amnezia; they can still appear in a full-access export). They are skipped
// QUIETLY — they are not proxy nodes, so listing them as "unsupported
// protocols" would only muddy the refusal message.
var amneziaServiceContainers = map[string]bool{
	"amnezia-torwebsite":  true,
	"amnezia-dns":         true,
	"amnezia-sftp":        true,
	"amnezia-socks5proxy": true,
	"none":                true,
}

// amneziaLastConfig extracts and returns the per-protocol "last_config" string
// (every Amnezia protocol sub-object stores its real payload there).
func amneziaLastConfig(sub json.RawMessage) (string, error) {
	var s struct {
		LastConfig string `json:"last_config"`
	}
	if err := json.Unmarshal(sub, &s); err != nil {
		return "", E.New("protocol object did not unmarshal: ", err)
	}
	if strings.TrimSpace(s.LastConfig) == "" {
		return "", E.New("protocol object has no last_config")
	}
	return s.LastConfig, nil
}

// amneziaXrayPart: last_config IS a full Xray client config (outbounds[0] =
// the real node). It is handed to the existing Xray-JSON ingestion verbatim.
func amneziaXrayPart(sub json.RawMessage, _ *amneziaExport) (amneziaPart, error) {
	lc, err := amneziaLastConfig(sub)
	if err != nil {
		return amneziaPart{}, err
	}
	if _, ok := looksLikeJSON(lc); !ok {
		return amneziaPart{}, E.New("xray last_config is not JSON")
	}
	return amneziaPart{kind: amneziaPartXrayJSON, body: lc}, nil
}

// amneziaWGPart: wireguard/awg last_config is a JSON whose "config" field
// holds the complete wg-quick / AmneziaWG INI (client-side exports carry real
// key material; only the "DNS = $PRIMARY_DNS, $SECONDARY_DNS" line keeps its
// placeholders, and AWGSingboxTxt ignores unknown keys — InHive owns DNS
// centrally anyway). The INI goes through the SAME AWGSingboxTxt path as a
// pasted .conf, so the two imports can never drift. An awg-obfuscated
// "wireguard" container (processNativeWireGuardConfig) carries its Jc/Jmin/…
// inline in the INI, which AWGSingboxTxt already parses.
func amneziaWGPart(sub json.RawMessage, _ *amneziaExport) (amneziaPart, error) {
	lc, err := amneziaLastConfig(sub)
	if err != nil {
		return amneziaPart{}, err
	}
	var s struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal([]byte(lc), &s); err != nil {
		return amneziaPart{}, E.New("wireguard last_config did not unmarshal: ", err)
	}
	if !looksLikeAWGConf(s.Config) {
		return amneziaPart{}, E.New("wireguard last_config carries no [Interface] config")
	}
	return amneziaPart{kind: amneziaPartWGConf, body: s.Config}, nil
}

// amneziaSSPart: shadowsocks last_config is the classic ss-libev client JSON.
// hostName is the documented fallback when the JSON omits the server field.
func amneziaSSPart(sub json.RawMessage, top *amneziaExport) (amneziaPart, error) {
	lc, err := amneziaLastConfig(sub)
	if err != nil {
		return amneziaPart{}, err
	}
	// server_port is a STRING in real exports (the template substitutes
	// "$SHADOWSOCKS_SERVER_PORT" inside quotes); accept a bare number too.
	var s struct {
		Server     string          `json:"server"`
		ServerPort json.RawMessage `json:"server_port"`
		Password   string          `json:"password"`
		Method     string          `json:"method"`
	}
	if err := json.Unmarshal([]byte(lc), &s); err != nil {
		return amneziaPart{}, E.New("shadowsocks last_config did not unmarshal: ", err)
	}
	server := orDefault(s.Server, top.HostName)
	if server == "" || s.Method == "" {
		return amneziaPart{}, E.New("shadowsocks last_config missing server/method")
	}
	port := int(toUInt16(strings.Trim(string(s.ServerPort), `"`), 0))
	uri := buildSSURI(s.Method, s.Password, server, port, "", "")
	return amneziaPart{kind: amneziaPartURI, body: uri}, nil
}

// amneziaParts decodes the vpn:// body and converts every supported container,
// in input order except that the defaultContainer's node goes FIRST (that is
// the one the Amnezia user actually connects with). A zero-node outcome is a
// HARD error that names the unsupported protocol(s) — the file was read fine,
// the protocol is simply not ours yet, and the user must be able to see that.
func amneziaParts(body string) ([]amneziaPart, error) {
	raw, err := decodeAmneziaVPN(body)
	if err != nil {
		return nil, err
	}
	var exp amneziaExport
	if err := json.Unmarshal(raw, &exp); err != nil {
		return nil, E.New("Amnezia vpn:// payload is not valid JSON: ", err)
	}
	if len(exp.Containers) == 0 {
		if exp.isAPIKey() {
			return nil, E.New("this vpn:// link is an Amnezia API key (Free/Premium service), not a server config — it cannot be imported")
		}
		return nil, E.New("Amnezia config contains no protocol containers")
	}

	baseName := orDefault(exp.Description, exp.HostName)
	var parts []amneziaPart
	var unsupported []string
	for _, rawC := range exp.Containers {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(rawC, &obj); err != nil {
			skip("amnezia", "container entry did not unmarshal: "+err.Error())
			continue
		}
		var id string
		if idRaw, ok := obj["container"]; ok {
			_ = json.Unmarshal(idRaw, &id)
		}
		if amneziaServiceContainers[id] {
			skip("amnezia", "service container "+id+" is not a proxy node")
			continue
		}
		h, known := amneziaHandlers[id]
		if !known {
			unsupported = append(unsupported, orDefault(id, "<unnamed>"))
			skip("amnezia", "unknown container type "+id)
			continue
		}
		if h.convert == nil {
			unsupported = append(unsupported, h.label)
			skip("amnezia", h.label+" container is not supported yet")
			continue
		}
		sub, ok := obj[h.key]
		if !ok {
			skip("amnezia", id+" container carries no '"+h.key+"' object")
			continue
		}
		part, cerr := h.convert(sub, &exp)
		if cerr != nil {
			skip("amnezia-"+h.key, cerr.Error())
			continue
		}
		part.name = baseName
		part.label = h.label
		if id == exp.DefaultContainer && len(parts) > 0 {
			parts = append([]amneziaPart{part}, parts...)
		} else {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		if len(unsupported) > 0 {
			return nil, E.New("Amnezia config: protocol container(s) not supported yet: ", strings.Join(unsupported, ", "))
		}
		return nil, E.New("Amnezia config: no importable nodes found")
	}
	// Several containers sharing one description: suffix the protocol so the
	// node list stays tellable-apart ("Osnova (Xray)", "Osnova (AmneziaWG)").
	if len(parts) > 1 && baseName != "" {
		for i := range parts {
			parts[i].name = baseName + " (" + parts[i].label + ")"
		}
	}
	return parts, nil
}

// amneziaRenameRecord stamps the container's display name onto one produced
// record: #fragment for a share-link URI, "tag" for a JSON-fallback node.
func amneziaRenameRecord(rec, name string) string {
	if name == "" || rec == "" {
		return rec
	}
	if strings.HasPrefix(rec, "{") {
		if renamed, ok := minifyNodeJSON(json.RawMessage(rec), name); ok {
			return renamed
		}
		return rec
	}
	return renameURIFragment(rec, name)
}

// ingestAmneziaVPN is the Parse-path consumer (GenerateConfigLite): it returns
// a newline-joined body of share-link URIs / raw INI chunks that the existing
// dispatchers understand. ok=false only when the body is not a vpn:// link at
// all; a vpn:// body that cannot be imported returns ok=true + a hard error
// (never a silent fallthrough into "No outbounds found").
func ingestAmneziaVPN(body string) (string, bool, error) {
	if !looksLikeAmneziaVPN(body) {
		return "", false, nil
	}
	parts, err := amneziaParts(body)
	if err != nil {
		return "", true, err
	}
	var lines []string
	for _, p := range parts {
		switch p.kind {
		case amneziaPartURI:
			for _, u := range strings.Split(p.body, "\n") {
				if u != "" {
					lines = append(lines, amneziaRenameRecord(u, p.name))
				}
			}
		case amneziaPartXrayJSON:
			uris, ok := ingestJSON(p.body)
			if !ok {
				skip("amnezia-xray", "last_config carries no importable outbounds")
				continue
			}
			for _, u := range strings.Split(uris, "\n") {
				lines = append(lines, amneziaRenameRecord(u, p.name))
			}
		case amneziaPartWGConf:
			// Prefer the canonical wg:// / awg:// URI (round-trips through the
			// endpoint canonicalizer). A tunnel that cannot round-trip goes in as
			// the raw INI chunk — the [Interface] dispatcher parses it natively.
			recs, ok := convertAWGConfEntries(p.body)
			gotURI := false
			if ok {
				for _, r := range recs {
					if !strings.HasPrefix(r, "{") {
						lines = append(lines, amneziaRenameRecord(r, p.name))
						gotURI = true
					}
				}
			}
			if !gotURI {
				lines = append(lines, p.body)
			}
		}
	}
	if len(lines) == 0 {
		return "", true, E.New("Amnezia config: nodes were recognized but none could be converted")
	}
	return strings.Join(lines, "\n"), true, nil
}

// convertAmneziaEntries is the ConvertToShareLinks consumer: one record per
// node (canonical URI or minified node JSON), input order, same error contract
// as ingestAmneziaVPN.
func convertAmneziaEntries(body string) ([]string, bool, error) {
	if !looksLikeAmneziaVPN(body) {
		return nil, false, nil
	}
	parts, err := amneziaParts(body)
	if err != nil {
		return nil, true, err
	}
	var records []string
	for _, p := range parts {
		switch p.kind {
		case amneziaPartURI:
			for _, u := range strings.Split(p.body, "\n") {
				if u != "" {
					records = append(records, amneziaRenameRecord(u, p.name))
				}
			}
		case amneziaPartXrayJSON:
			recs, ok := convertJSONEntries(p.body)
			if !ok {
				skip("amnezia-xray", "last_config carries no importable outbounds")
				continue
			}
			for _, r := range recs {
				records = append(records, amneziaRenameRecord(r, p.name))
			}
		case amneziaPartWGConf:
			recs, ok := convertAWGConfEntries(p.body)
			if !ok {
				skip("amnezia-wireguard", "config INI did not parse")
				continue
			}
			for _, r := range recs {
				records = append(records, amneziaRenameRecord(r, p.name))
			}
		}
	}
	if len(records) == 0 {
		return nil, true, E.New("Amnezia config: nodes were recognized but none could be converted")
	}
	return records, true, nil
}
