package ray2sing

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// normalizeSocksVersion maps foreign spellings of the socks version param onto
// the exact lowercase {"4","4a","5"} that sing's socks.ParseVersion accepts
// (case-sensitive switch; anything else kills the node at outbound creation).
// Handles "4A" (curl/proxychains uppercase), full scheme names ("socks5",
// "socks4a"), and the curl remote-DNS convention "5h"/"socks5h" (remote DNS is
// SOCKS5 default behavior in sing-box, so it maps to plain "5"). Unknown values
// return a diagnosable error instead of passing through.
func normalizeSocksVersion(v string) (string, error) {
	s := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "socks")
	switch s {
	case "4", "4a", "5":
		return s, nil
	case "5h":
		return "5", nil
	}
	return "", E.New("unknown socks version '" + v + "'")
}

func SocksSingbox(url string) (*T.Outbound, error) {
	// curl-конвенция: socks5://host без порта = 1080 (free-proxy списки).
	// Дефолт 0 давал «распарсилось» с server_port:0 — мёртвая нода без ошибки.
	u, err := ParseUrl(url, 1080)
	if err != nil {
		return nil, err
	}
	// v2rayN/NekoBox экспортируют креды как socks://BASE64(user:pass)@host —
	// decode-then-validate (как у ss://): без декода юзернеймом становился
	// сам блоб и авторизация молча не сходилась никогда.
	if u.Password == "" && u.Username != "" && looksLikeBase64(u.Username) {
		if dec, err := decodeBase64IfNeeded(u.Username); err == nil {
			if user, pass, ok := strings.Cut(dec, ":"); ok && isPrintableText(dec) {
				u.Username, u.Password = user, pass
			}
		}
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
	if version, err := getOneOf(u.Params, "v", "ver", "version"); err == nil && version != "" {
		normalized, err := normalizeSocksVersion(version)
		if err != nil {
			return nil, err
		}
		opts.Version = normalized
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
