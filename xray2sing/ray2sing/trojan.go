package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func TrojanSingbox(trojanURL string) (*T.Outbound, error) {
	u, err := ParseUrl(trojanURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params

	// XTLS-Vision flow has NO field in sing-box's TrojanOutboundOptions (unlike VLESS).
	// Silently dropping it builds a plain Trojan-TLS node that dies in the handshake
	// against a Vision server. Surface a diagnosable error instead, mirroring the VLESS
	// encryption guard. Fires only when flow is explicitly non-empty/non-none. (Audit 2026-06-26.)
	if flow := decoded["flow"]; flow != "" && flow != "none" {
		return nil, E.New("Trojan flow '" + flow + "' (XTLS-Vision) not supported: sing-box TrojanOutboundOptions has no flow field")
	}

	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}

	// trojan-gfw treats the entire userinfo as the password. Go's net/url
	// splits userinfo on the first ':', so a password with an unescaped colon
	// lands in u.Password — recombine it to avoid silent truncation.
	password := u.Username
	if u.Password != "" {
		password = u.Username + ":" + u.Password
	}

	return &T.Outbound{
		Tag:  u.Name,
		Type: "trojan",
		Options: &T.TrojanOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			Password:                    password,
			OutboundTLSOptionsContainer: getTLSOptions(decoded),
			Transport:                   transportOptions,
			Multiplex:                   getMuxOptions(decoded),
		},
	}, nil
}
