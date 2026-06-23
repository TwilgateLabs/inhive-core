package ray2sing

import (
	"strconv"
	"strings"
	"time"

	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// AnyTLSSingbox parses an anytls:// share-link (a NekoBox/sublink-worker
// community convention; sing-box itself only documents the JSON form) into a
// sing-box AnyTLS outbound. The userinfo carries the password
// (anytls://password@host:port?sni=&insecure=&alpn=&fp=#name). AnyTLS always
// runs over TLS — the dialer rejects the outbound without TLS.Enabled and also
// rejects tcp_fast_open, so neither is wired here.
func AnyTLSSingbox(anytlsURL string) (*T.Outbound, error) {
	u, err := ParseUrl(anytlsURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params

	// Go's net/url splits userinfo on the first ':'; recombine so a password
	// with an unescaped colon is not silently truncated (mirror trojan.go).
	password := u.Username
	if u.Password != "" {
		password = u.Username + ":" + u.Password
	}

	tlsOptions := getTLSOptions(decoded)
	// AnyTLS requires TLS (outbound rejects it otherwise). Share-links rarely
	// carry an explicit tls= key, so force-enable when getTLSOptions found none,
	// taking the SNI from sni/host/server.
	if tlsOptions.TLS == nil {
		serverName := getOneOfN(decoded, "", "sni", "host")
		if serverName == "" {
			serverName = u.Hostname
		}
		insecure, e := getOneOf(decoded, "insecure", "allowinsecure")
		if e != nil {
			insecure = "false"
		}
		tlsOpts := &T.OutboundTLSOptions{
			Enabled:    true,
			ServerName: serverName,
			Insecure:   insecure == "true" || insecure == "1",
		}
		if alpn := decoded["alpn"]; alpn != "" {
			tlsOpts.ALPN = strings.Split(alpn, ",")
		}
		if fp := decoded["fp"]; fp != "" {
			tlsOpts.UTLS = &T.OutboundUTLSOptions{
				Enabled:     true,
				Fingerprint: fp,
			}
		}
		tlsOptions.TLS = tlsOpts
	} else {
		tlsOptions.TLS.Enabled = true
	}

	opts := &T.AnyTLSOutboundOptions{
		DialerOptions:               getDialerOptions(decoded),
		ServerOptions:               u.GetServerOption(),
		Password:                    password,
		OutboundTLSOptionsContainer: tlsOptions,
	}

	// Optional idle-session tuning (seconds), mirroring hop-interval parsing.
	if v := getOneOfN(decoded, "", "idle-session-check-interval", "idlesessioncheckinterval"); v != "" {
		if secs, e := strconv.Atoi(strings.TrimSpace(v)); e == nil && secs > 0 {
			opts.IdleSessionCheckInterval = badoption.Duration(time.Duration(secs) * time.Second)
		}
	}
	if v := getOneOfN(decoded, "", "idle-session-timeout", "idlesessiontimeout"); v != "" {
		if secs, e := strconv.Atoi(strings.TrimSpace(v)); e == nil && secs > 0 {
			opts.IdleSessionTimeout = badoption.Duration(time.Duration(secs) * time.Second)
		}
	}
	if v := getOneOfN(decoded, "", "min-idle-session", "minidlesession"); v != "" {
		if n, e := strconv.Atoi(strings.TrimSpace(v)); e == nil && n > 0 {
			opts.MinIdleSession = n
		}
	}

	return &T.Outbound{
		Tag:     u.Name,
		Type:    "anytls",
		Options: opts,
	}, nil
}
