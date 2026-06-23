package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func SocksSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	opts := T.SOCKSOutboundOptions{
		ServerOptions: u.GetServerOption(),
		Username:      u.Username,
		Password:      u.Password,
	}
	out := &T.Outbound{
		Type:    C.TypeSOCKS,
		Tag:     u.Name,
		Options: &opts,
	}
	if version, err := getOneOf(u.Params, "v", "ver", "version"); err == nil {
		opts.Version = version
	} else {
		// Derive version from the URL scheme when not given explicitly:
		// socks4/socks4a -> "4", socks5/socks5h -> "5". Plain socks:// keeps the
		// sing-box default (5). (Audit 2026-06-23 — socks4/5 scheme aliases.)
		switch u.Scheme {
		case "socks4", "socks4a":
			opts.Version = "4"
		case "socks5", "socks5h":
			opts.Version = "5"
		}
	}
	// Tunnel UDP over the TCP stream only on explicit ?uot=1. Forcing it on by
	// default would break SOCKS servers that natively support UDP ASSOCIATE.
	if toBool(getOneOfN(u.Params, "", "uot"), false) {
		opts.UDPOverTCP = &T.UDPOverTCPOptions{
			Enabled: true,
		}
	}
	// if net, err := getOneOf(u.Params, "net", "network"); err == nil {
	// 	out.SocksOptions.Network= net
	// }
	return out, nil
}
