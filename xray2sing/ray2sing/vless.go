package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func VlessSingbox(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// fmt.Printf("Port %v deco=%v", port, decoded)
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
			Flow:                        decoded["flow"],
			OutboundTLSOptionsContainer: tlsOptions,
			Transport:                   transportOptions,
			Multiplex:                   getMuxOptions(decoded),
		},
	}, nil
}
