package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func HttpSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	opts := T.HTTPOutboundOptions{
		ServerOptions: u.GetServerOption(),
		Username:      u.Username,
		Password:      u.Password,
	}
	out := &T.Outbound{
		Type:    C.TypeHTTP,
		Tag:     u.Name,
		Options: &opts,
	}
	// Enable TLS only when tls is explicitly truthy (tls/1/true) or an SNI is
	// given. A bare tls=none/0/false must NOT wrap a plaintext HTTP proxy in TLS.
	tlsVal := getOneOfN(u.Params, "", "tls")
	sni := getOneOfN(u.Params, "", "sni")
	if tlsVal == "tls" || tlsVal == "1" || tlsVal == "true" || sni != "" {
		tlsOpts := &T.OutboundTLSOptions{
			Enabled:    true,
			ServerName: sni,
		}
		if insecure, err := getOneOf(u.Params, "insecure"); err == nil {
			tlsOpts.Insecure = toBool(insecure, false)
		}
		opts.OutboundTLSOptionsContainer.TLS = tlsOpts
	}
	if path, err := getOneOf(u.Params, "path"); err == nil {
		opts.Path = path
	}
	// if net, err := getOneOf(u.Params, "net", "network"); err == nil {
	// 	out.SocksOptions.Network= net
	// }
	return out, nil
}

func HttpsSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	opts := T.HTTPOutboundOptions{
		ServerOptions: u.GetServerOption(),
		Username:      u.Username,
		Password:      u.Password,
	}
	out := &T.Outbound{
		Type:    C.TypeHTTP,
		Tag:     u.Name,
		Options: &opts,
	}
	opts.OutboundTLSOptionsContainer.TLS = &T.OutboundTLSOptions{
		Enabled: true,
	}
	if sni, err := getOneOf(u.Params, "sni"); err == nil {
		opts.OutboundTLSOptionsContainer.TLS.ServerName = sni
	}
	if insecure, err := getOneOf(u.Params, "insecure"); err == nil {
		// Secure-default parse: insecure=false/no/off/0 → verify (false). The old
		// `insecure != "0"` inverted it — every value except literal "0" (incl.
		// "false") disabled cert verification. Matches HttpSingbox at http.go:33.
		opts.OutboundTLSOptionsContainer.TLS.Insecure = toBool(insecure, false)
	}

	if path, err := getOneOf(u.Params, "path"); err == nil {
		opts.Path = path
	}

	// if net, err := getOneOf(u.Params, "net", "network"); err == nil {
	// 	out.SocksOptions.Network= net
	// }
	return out, nil
}
