package ray2sing

import (
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func NaiveSingbox(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// naive is TLS-inside-cronet only; there is no non-TLS mode. Any foreign
	// security value (none/xtls/whatever the source panel used) must degrade to
	// tls UNCONDITIONALLY — an explicit security=none would make getTLSOptions
	// return a nil TLS container, and protocol/naive/outbound.go then fails with
	// ErrTLSRequired at creation (silent node death). Same policy as the
	// fp/minVersion/reality force-clearing below.
	decoded["security"] = "tls"

	// fmt.Printf("Port %v deco=%v", port, decoded)
	// Reality is now set inside getTLSOptions (shared by vless/vmess/trojan/naive).
	tlsOptions := getTLSOptions(decoded)
	// naive terminates TLS inside cronet (Chromium), not in our TLS stack, so
	// protocol/naive/outbound.go REJECTS a whole list of TLS knobs at construction
	// time. getTLSOptions is shared with vless/vmess/trojan and happily sets every
	// one of them from the URI, so each must be zeroed here or the node dies.
	//
	// Our fork does not fail the whole config on such a rejection — the outbound is
	// swapped for InvalidConfig (adapter/outbound/manager.go:315) — which makes the
	// failure mode SILENT: one foreign-subscription naive node carrying fp= turns
	// into a permanently dead server with a red ping and no user-visible reason.
	// That is exactly the Universal Client contract we must not break.
	//
	// Keep this list in sync with the guards in protocol/naive/outbound.go:49-85.
	// alpn/insecure/disable_sni were already handled; fp/min/max/reality were not
	// (audit 2026-07-30, same bug class as uTLS-on-QUIC).
	if tlsOptions.TLS != nil {
		tlsOptions.TLS.ALPN = nil
		tlsOptions.TLS.Insecure = false
		tlsOptions.TLS.DisableSNI = false
		// :82 "uTLS is not supported on naive outbound" — cronet builds its own
		// ClientHello, a fingerprint here cannot be honored anyway.
		tlsOptions.TLS.UTLS = nil
		// :58/:61 "min_version/max_version is not supported on naive outbound".
		tlsOptions.TLS.MinVersion = ""
		tlsOptions.TLS.MaxVersion = ""
		// :85 "reality is not supported on naive outbound". naive+reality is not a
		// real-world combination, but a stray security=reality in a share link must
		// degrade to plain TLS rather than kill the node.
		tlsOptions.TLS.Reality = nil
	}
	// quic_congestion_control: sing-box's acceptance switch is exact-lowercase
	// {"","bbr","bbr2","cubic","reno"} (protocol/naive/outbound.go:176-190) and
	// its default arm kills the node at creation. Normalize case, map the
	// NaiveProxy/cronet doc spelling "bbrv2" -> "bbr2", and degrade anything
	// else to "" (cronet default) — normalizePacketEncoding's degrade-don't-die
	// policy.
	qcc := strings.ToLower(strings.TrimSpace(getOneOfN(decoded, "", "quic_congestion_control")))
	if qcc == "bbrv2" {
		qcc = "bbr2"
	}
	switch qcc {
	case "", "bbr", "bbr2", "cubic", "reno":
	default:
		qcc = ""
	}

	uot := T.UDPOverTCPOptions{
		Enabled: getOneOfN(decoded, "", "uot") != "false" && getOneOfN(decoded, "", "uot") != "0",
	}

	return &T.Outbound{
		Tag:  u.Name,
		Type: C.TypeNaive,
		Options: &T.NaiveOutboundOptions{
			DialerOptions:               getDialerOptions(decoded),
			ServerOptions:               u.GetServerOption(),
			Username:                    u.Username,
			Password:                    u.Password,
			InsecureConcurrency:         toInt(getOneOfN(decoded, "0", "insecure_concurrency")),
			ExtraHeaders:                GetHttpHeaders(getOneOfN(decoded, "", "header")),
			QUIC:                        u.Scheme == "naive+quic" || getOneOfN(decoded, "", "quic") != "",
			QUICCongestionControl:       qcc,
			OutboundTLSOptionsContainer: tlsOptions,
			UDPOverTCP:                  &uot,
		},
	}, nil
}

func GetHttpHeaders(header string) badoption.HTTPHeader {
	kvs := strings.Split(header, ",")
	res := badoption.HTTPHeader{}

	for _, raw := range kvs {
		splt := strings.SplitN(raw, ":", 2)
		if len(splt) != 2 {
			continue
		}
		k, v := splt[0], splt[1]
		if _, ok := res[k]; !ok {
			res[k] = []string{}
		}
		res[k] = append(res[k], v)
	}
	return res
}
