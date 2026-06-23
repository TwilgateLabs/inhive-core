package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

func TrojanSingbox(trojanURL string) (*T.Outbound, error) {
	u, err := ParseUrl(trojanURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params

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
