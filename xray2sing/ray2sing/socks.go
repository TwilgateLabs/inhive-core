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
