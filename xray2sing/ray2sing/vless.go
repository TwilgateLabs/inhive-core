package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// normalizeVlessFlow maps upstream-Xray flow variants onto the values the
// (upstream, non-forked) sing-vmess dependency accepts ("" or "xtls-rprx-vision").
// 'xtls-rprx-vision-udp443' = same as vision but doesn't intercept UDP 443; sing-box's
// vision impl already declines UDP-over-vision unconditionally, so the alias is
// semantically sound and stops the node from dying at outbound construction.
// (Audit 2026-06-23: silent node death on a real, growing flow variant.)
func normalizeVlessFlow(flow string) string {
	switch flow {
	case "xtls-rprx-vision-udp443":
		return "xtls-rprx-vision"
	}
	return flow
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

	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}

	// Reality is now set inside getTLSOptions (shared by vless/vmess/trojan/naive).
	tlsOptions := getTLSOptions(decoded)

	packetEncoding := decoded["packetencoding"]
	if packetEncoding == "" {
		packetEncoding = "xudp"
	}

	return &T.Outbound{
		Tag:  u.Name,
		Type: "vless",
		Options: &T.VLESSOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			UUID:                        u.Username,
			PacketEncoding:              &packetEncoding,
			Flow:                        normalizeVlessFlow(decoded["flow"]),
			OutboundTLSOptionsContainer: tlsOptions,
			Transport:                   transportOptions,
			Multiplex:                   getMuxOptions(decoded),
		},
	}, nil
}
