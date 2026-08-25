package ray2sing

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"

	"encoding/json"
)

func decodeVmess(vmessConfig string) (map[string]string, error) {
	// Strip the scheme scheme-agnostically: the dispatch table also registers
	// this parser for svmess:// and xvmess:// (9 chars), so a hardcoded [8:]
	// left a leading '/' in the base64 body and silently lost every such link.
	vmessData := vmessConfig
	if i := strings.Index(vmessConfig, "://"); i >= 0 {
		vmessData = vmessConfig[i+3:]
	}
	// The body is an opaque base64 blob with no native fragment support, but
	// both real-world exporters (sing-box/Streisand style vmess://<b64>#name)
	// and our own Happ per-node rename (renameURIFragment in json_ingest.go)
	// append '#<name>' — which is not legal base64. Split it off before
	// decoding and let it override "ps" as the display name.
	body, frag, hasFrag := strings.Cut(vmessData, "#")
	decodedData, err := decodeBase64FaultTolerant(body)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	err = json.Unmarshal([]byte(decodedData), &data)
	if err != nil {
		return nil, err
	}
	strdata := convertToStrings(data)
	if hasFrag {
		if name, err := url.QueryUnescape(frag); err == nil && name != "" {
			strdata["ps"] = name
		}
	}
	return strdata, nil
}

// normalizeVmessSecurity maps foreign vmess "scy" vocabulary onto the set the
// (upstream) sing-vmess dependency accepts, which is an exact case-sensitive
// switch over {auto, none, zero, aes-128-cfb, aes-128-gcm, chacha20-poly1305}
// (sing-vmess client.go:36-55) — anything else kills the node at outbound
// creation. Unknown/legacy values fall back to "auto" (Xray parity: the client
// then negotiates a supported cipher) rather than passing through.
func normalizeVmessSecurity(scy string) string {
	s := strings.ToLower(strings.TrimSpace(scy))
	if s == "chacha20-ietf-poly1305" { // ss-spelling emitted by sloppy panels
		s = "chacha20-poly1305"
	}
	switch s {
	case "auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305":
		return s
	default: // "", uppercase variants already lowered above; anything else -> auto
		return "auto"
	}
}

func convertToStrings(data map[string]interface{}) map[string]string {
	stringMap := make(map[string]string)
	for key, value := range data {
		switch v := value.(type) {
		case string:
			stringMap[key] = v
		case float64:
			stringMap[key] = strconv.Itoa(int(v))
		// case map[string]interface{}:
		// 	stringMap[key] = convertToStrings(v)

		default:
			stringMap[key] = fmt.Sprintf("%v", v)
		}
	}
	return stringMap

}

func VmessSingbox(vmessURL string) (*T.Outbound, error) {
	decoded, err := decodeVmess(vmessURL)
	if err != nil {
		return nil, err
	}

	port := toUInt16(decoded["port"], 443)
	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}
	security := normalizeVmessSecurity(decoded["scy"])
	// Leave PacketEncoding empty (upstream/runtime default = disabled) unless the
	// subscription carries an explicit hint. Forcing xudp on a server without XUDP
	// support can silently mishandle UDP-associated traffic.
	packetEncoding := normalizePacketEncoding(decoded["packetEncoding"])
	// vmess base64 JSON carries no fingerprint field; default to chrome so the
	// TLS ClientHello isn't the trivially-detectable Go-default stack (DPI).
	if decoded["tls"] == "tls" && decoded["fp"] == "" {
		decoded["fp"] = "chrome"
	}
	return &T.Outbound{
		Tag:  decoded["ps"],
		Type: "vmess",
		Options: &T.VMessOutboundOptions{
			DialerOptions: getDialerOptions(decoded),
			ServerOptions: T.ServerOptions{
				Server:     decoded["add"],
				ServerPort: port,
			},
			UUID:          decoded["id"],
			Security:      security,
			AlterId:       toInt(decoded["aid"]),
			GlobalPadding: false,
			// Default false (upstream parity); no standard vmess base64 field
			// signals it, and runtime negotiates the bit on the wire. Only set
			// true on an explicit hint to stay safe on legacy non-TLS AEAD nodes.
			AuthenticatedLength:         decoded["authenticatedLength"] == "true",
			PacketEncoding:              packetEncoding,
			OutboundTLSOptionsContainer: getTLSOptions(decoded),
			Transport:                   transportOptions,
			Multiplex:                   getMuxOptions(decoded),
		},
	}, nil
}
