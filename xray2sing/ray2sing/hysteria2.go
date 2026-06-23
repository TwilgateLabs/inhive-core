package ray2sing

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// authorityPortRange matches a "host:A-B" port-range in the URL authority
// (after any "user:pass@"). Hysteria2 allows native port-hopping syntax like
// hysteria2://auth@host:20000-50000/?... but Go's url.Parse rejects a non-numeric
// port outright, so we must lift the range out of the raw URL before parsing.
var authorityPortRange = regexp.MustCompile(`^([^/?#]*@)?([^/?#@:]+):(\d+)-(\d+)([/?#].*|)$`)

// extractHostPortRange detects an "A-B" port range in the authority of a raw
// hysteria2 URL. If found it returns a rewritten URL whose authority carries the
// single low port (so url.Parse succeeds) plus the range as a sing-box "A:B"
// ServerPorts entry. If no range is present, ok is false and the URL is unchanged.
func extractHostPortRange(rawURL string) (rewritten, portRange string, ok bool) {
	const sep = "://"
	i := strings.Index(rawURL, sep)
	if i < 0 {
		return rawURL, "", false
	}
	scheme := rawURL[:i+len(sep)]
	rest := rawURL[i+len(sep):]
	m := authorityPortRange.FindStringSubmatch(rest)
	if m == nil {
		return rawURL, "", false
	}
	userinfo, host, low, high, tail := m[1], m[2], m[3], m[4], m[5]
	rewritten = scheme + userinfo + host + ":" + low + tail
	return rewritten, low + ":" + high, true
}

func Hysteria2Singbox(hysteria2Url string) (*T.Outbound, error) {
	hostPortRange, hasHostPortRange := "", false
	if rewritten, pr, ok := extractHostPortRange(hysteria2Url); ok {
		hysteria2Url = rewritten
		hostPortRange, hasHostPortRange = pr, true
	}
	u, err := ParseUrl(hysteria2Url, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	var ObfsOpts *T.Hysteria2Obfs
	ObfsOpts = nil
	if obfs, ok := decoded["obfs"]; ok && obfs != "" {
		ObfsOpts = &T.Hysteria2Obfs{
			Type:     obfs,
			Password: getOneOfN(decoded, "", "obfs-password", "obfs_password", "obfspassword"),
		}
	}

	valECH, hasECH := decoded["ech"]
	hasECH = hasECH && (valECH != "0")
	var ECHOpts *T.OutboundECHOptions
	ECHOpts = nil
	if hasECH {
		ECHOpts = &T.OutboundECHOptions{
			Enabled: hasECH,
		}
	}

	SNI := decoded["sni"]
	if SNI == "" {
		SNI = decoded["hostname"]
	}
	// turnRelay, err := u.GetRelayOptions()
	// if err != nil {
	// 	return nil, err
	// }
	pass := u.Username
	if u.Password != "" {
		pass += ":" + u.Password
	}
	h2opts := &T.Hysteria2OutboundOptions{
		ServerOptions: u.GetServerOption(),
		Obfs:          ObfsOpts,
		Password:      pass,
		OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
			TLS: &T.OutboundTLSOptions{
				Enabled:    true,
				Insecure:   decoded["insecure"] == "1",
				DisableSNI: isIPOnly(SNI),
				ServerName: SNI,
				ECH:        ECHOpts,
			},
		},
		// TurnRelay: turnRelay,
	}

	// bandwidth hints (upmbps/downmbps) — v2rayN/Happ hy2 export extension.
	// Mirrors hysteria1; enables Brutal congestion control (SendBPS/ReceiveBPS).
	if upMbps, e := strconv.Atoi(strings.TrimSpace(getOneOfN(decoded, "", "upmbps", "up"))); e == nil {
		h2opts.UpMbps = upMbps
	}
	if downMbps, e := strconv.Atoi(strings.TrimSpace(getOneOfN(decoded, "", "downmbps", "down"))); e == nil {
		h2opts.DownMbps = downMbps
	}

	// port hopping — sing-box expects 'A:B'. Sources, in precedence order:
	//   1. native host range (host:A-B), lifted out before ParseUrl above
	//   2. mport/ports query param
	if hasHostPortRange {
		h2opts.ServerPorts = badoption.Listable[string]{hostPortRange}
	} else if mp := getOneOfN(decoded, "", "mport", "ports"); mp != "" {
		h2opts.ServerPorts = badoption.Listable[string]{strings.ReplaceAll(mp, "-", ":")}
	}
	if len(h2opts.ServerPorts) > 0 {
		// honor an explicit hop-interval (seconds); default to 30s otherwise.
		h2opts.HopInterval = badoption.Duration(30 * time.Second)
		if hi := getOneOfN(decoded, "", "hop-interval", "hopinterval"); hi != "" {
			if secs, e := strconv.Atoi(strings.TrimSpace(hi)); e == nil && secs > 0 {
				h2opts.HopInterval = badoption.Duration(time.Duration(secs) * time.Second)
			}
		}
	}

	result := T.Outbound{
		Type:    "hysteria2",
		Tag:     u.Name,
		Options: h2opts,
	}

	return &result, nil
}
