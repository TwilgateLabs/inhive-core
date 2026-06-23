package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

// ShadowTLSSingbox parses a shadowtls:// share-link
//
//	shadowtls://password@host:port?version=3&sni=&fp=&alpn=#name
//
// ShadowTLS is almost always chained in front of Shadowsocks; the front is
// expressed via the parser's ' -> ' detour chaining (e.g.
// "shadowtls://... -> ss://..."). This parser only produces the standalone
// shadowtls outbound — the chain machinery lives in convert.go.
//
// TLS is mandatory for shadowtls, so getTLSOptions is forced on by seeding the
// security key; SNI/utls(fp)/alpn/insecure are all read from the query via the
// shared helper.
func ShadowTLSSingbox(url string) (*T.Outbound, error) {
	u, err := ParseUrl(url, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params

	// Version: 0 in the option defaults to 1 in the outbound, but the common
	// real-world default for share-links is 3. Honor an explicit ?version=.
	version := toInt(getOneOfN(decoded, "", "version"))
	if version == 0 {
		version = 3
	}

	// ShadowTLS always runs TLS; ensure getTLSOptions emits a TLS block.
	if decoded["security"] == "" && decoded["tls"] == "" {
		decoded["security"] = "tls"
	}

	// Share-links use the bare userinfo form `password@host`, which ParseUrl
	// stores in Username (no colon -> empty Password). Fall back to Username so
	// both `password@host` and `user:password@host` carry the secret.
	password := u.Password
	if password == "" {
		password = u.Username
	}

	result := T.Outbound{
		Type: C.TypeShadowTLS,
		Tag:  u.Name,
		Options: &T.ShadowTLSOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			Version:                     version,
			Password:                    password,
			OutboundTLSOptionsContainer: getTLSOptions(decoded),
		},
	}
	return &result, nil
}
