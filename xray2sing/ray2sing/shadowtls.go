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
	switch version {
	case 1, 2, 3:
		// exactly the set sing-shadowtls' NewClient accepts
	default:
		// unset (0), non-numeric (toInt->0), or out-of-range (4, -1, ...) —
		// clamp to the real-world default instead of letting sing-shadowtls
		// reject the node with "unknown protocol version" at creation.
		version = 3
	}

	// ShadowTLS always runs TLS; ensure getTLSOptions emits a TLS block. Any
	// share-link value other than reality (including generator-emitted
	// "security=none"/"tls=none" or garbage) must not defeat this — ShadowTLS
	// is definitionally TLS-only, unlike vless/trojan where "none" is
	// meaningful. Without this, security=none leaves the TLS block nil and the
	// outbound dies with ErrTLSRequired at creation.
	if decoded["security"] != "reality" && decoded["tls"] != "reality" {
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
