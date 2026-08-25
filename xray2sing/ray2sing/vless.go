package ray2sing

import (
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// normalizeVlessFlow maps upstream-Xray flow variants onto the values the
// (upstream, non-forked) sing-vmess dependency accepts ("" or "xtls-rprx-vision").
// The input is trimmed+lowercased first: url_schema.go normalizes only the query
// KEY, so "None"/"XTLS-RPRX-VISION" survive uppercase in the value.
//   - ""/"none" (Xray's disabled spelling — trojan.go already whitelists it) -> "".
//   - 'xtls-rprx-vision-udp443' = same as vision but doesn't intercept UDP 443;
//     sing-box's vision impl already declines UDP-over-vision unconditionally, so
//     the alias is semantically sound.
//   - Legacy pre-Vision XTLS flows (xtls-rprx-origin/direct/splice[-udp443]) have
//     NO sing-box equivalent; silently stripping them would yield a plaintext-flow
//     node that still fails the handshake against a legacy-XTLS-only server
//     (silent-fail class, forbidden), so they get a diagnosable error — mirroring
//     the encryption guard below and trojan.go's flow guard.
//   - Anything else is unknown vocabulary -> diagnosable error rather than letting
//     sing-vmess kill the node at creation with a cryptic 'unsupported flow'.
//
// (Audit 2026-06-23 + 2026-08-25: silent node death on real flow variants.)
func normalizeVlessFlow(flow string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(flow)) {
	case "", "none":
		return "", nil
	case "xtls-rprx-vision", "xtls-rprx-vision-udp443":
		return "xtls-rprx-vision", nil
	case "xtls-rprx-origin", "xtls-rprx-origin-udp443",
		"xtls-rprx-direct", "xtls-rprx-direct-udp443",
		"xtls-rprx-splice", "xtls-rprx-splice-udp443":
		return "", E.New("legacy XTLS flow '" + flow + "' is not supported by sing-box; the server must be migrated to xtls-rprx-vision or plain TLS")
	default:
		return "", E.New("unknown VLESS flow '" + flow + "'")
	}
}

func VlessSingbox(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// fmt.Printf("Port %v deco=%v", port, decoded)

	// VLESS Encryption (post-quantum mlkem768x25519plus, Xray PR #5067) is a distinct
	// anti-DPI handshake that neither sing-box nor the sing-vmess dep implements yet.
	// Silently dropping the field yields a plaintext-handshake config the server rejects
	// (silent node death). Surface an explicit, diagnosable error until runtime support
	// lands. (Audit 2026-06-23 critic.)
	if enc := decoded["encryption"]; enc != "" && enc != "none" {
		return nil, E.New("VLESS encryption not supported yet (got '" + enc + "'); needs the ML-KEM/x25519plus handshake which sing-box has not implemented")
	}

	flow, err := normalizeVlessFlow(decoded["flow"])
	if err != nil {
		return nil, err
	}

	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}

	// Reality is now set inside getTLSOptions (shared by vless/vmess/trojan/naive).
	tlsOptions := getTLSOptions(decoded)

	packetEncoding := decoded["packetencoding"]
	if packetEncoding == "" {
		packetEncoding = "xudp"
	} else {
		// Share links carry Xray vocabulary ("none" = disabled); sing-box
		// panics-into-error on anything outside ""/packetaddr/xudp.
		packetEncoding = normalizePacketEncoding(packetEncoding)
	}

	return &T.Outbound{
		Tag:  u.Name,
		Type: "vless",
		Options: &T.VLESSOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			UUID:                        u.Username,
			PacketEncoding:              &packetEncoding,
			Flow:                        flow,
			OutboundTLSOptionsContainer: tlsOptions,
			Transport:                   transportOptions,
			Multiplex:                   getMuxOptions(decoded),
		},
	}, nil
}
