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
	if decoded["security"] == "" {
		decoded["security"] = "tls"
	}

	// fmt.Printf("Port %v deco=%v", port, decoded)
	// Reality is now set inside getTLSOptions (shared by vless/vmess/trojan/naive).
	tlsOptions := getTLSOptions(decoded)
	// sing-box naive outbound rejects alpn/insecure/disable_sni on the TLS block
	// (it negotiates ALPN itself inside cronet). Zero them out after getTLSOptions
	// or the whole outbound fails to build.
	if tlsOptions.TLS != nil {
		tlsOptions.TLS.ALPN = nil
		tlsOptions.TLS.Insecure = false
		tlsOptions.TLS.DisableSNI = false
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
			QUICCongestionControl:       getOneOfN(decoded, "", "quic_congestion_control"),
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
