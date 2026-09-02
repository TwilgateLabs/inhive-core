package ray2sing

import (
	"fmt"
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
var authorityPortRange = regexp.MustCompile(`^([^/?#]*@)?([^/?#@:]+):(\d+(?:[-,]\d+)+)([/?#].*|)$`)

// normalizeHopPorts переводит официальный hy2-синтаксис хоппинга
// ("443,8443", "500-1000", "500-1000,2000") в формат sing-box: список
// записей "A:B" (одиночный порт = "p:p" — sing-quic ParsePorts голый порт
// без ':' отвергает, нода молча умирала). Возвращает записи и низший порт.
func normalizeHopPorts(spec string) (entries []string, low string) {
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, b, isRange := strings.Cut(part, "-")
		if !isRange {
			b = a
		}
		entries = append(entries, a+":"+b)
		if low == "" {
			low = a
		}
	}
	return entries, low
}

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
	userinfo, host, spec, tail := m[1], m[2], m[3], m[4]
	_, low := normalizeHopPorts(spec)
	rewritten = scheme + userinfo + host + ":" + low + tail
	return rewritten, spec, true
}


// parseMbpsHint терпит юниты официального hy2-формата («100 mbps», «2 gbps»):
// голый Atoi молча ронял подсказку и Brutal не включался.
func parseMbpsHint(v string) int {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return 0
	}
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	n, err := strconv.Atoi(v[:i])
	if err != nil {
		return 0
	}
	if strings.Contains(v[i:], "g") {
		n *= 1000
	} else if strings.Contains(v[i:], "k") {
		// kbps → мегабиты, округляя вверх до 1
		if n > 0 && n < 1000 {
			n = 1
		} else {
			n /= 1000
		}
	}
	return n
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
	// Официальный hy2-параметр pinSHA256 пиннит ХЕШ СЕРТИФИКАТА; у sing-box
	// поля с такой семантикой нет (certificate_public_key_sha256 — хеш
	// ПУБЛИЧНОГО КЛЮЧА, не эквивалент). Молчаливый дроп якоря доверия =
	// нода с self-signed сертом «подключается» мимо заявленной проверки —
	// честная ошибка вместо ложной безопасности.
	if pin := getOneOfN(decoded, "", "pinsha256", "pin_sha256"); pin != "" && !toBool(decoded["insecure"], false) {
		// С insecure=1 пин дропается безопасно (verify и так выключен, узел
		// работает); БЕЗ insecure пин — единственный якорь доверия self-signed
		// серта, его тихий дроп = либо криптичная смерть на verify, либо
		// ложная безопасность.
		return nil, fmt.Errorf("hysteria2 pinSHA256 (certificate pinning) is not supported by the sing-box core; use insecure=1 if the server is self-signed")
	}
	h2opts := &T.Hysteria2OutboundOptions{
		ServerOptions: u.GetServerOption(),
		Obfs:          ObfsOpts,
		Password:      pass,
		OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
			TLS: &T.OutboundTLSOptions{
				Enabled:    true,
				Insecure:   toBool(decoded["insecure"], false),
				DisableSNI: isIPOnly(SNI),
				ServerName: SNI,
				ECH:        ECHOpts,
			},
		},
		// TurnRelay: turnRelay,
	}

	// explicit alpn= from the URI (hy2 export extension). When absent, leave ALPN nil
	// so sing-quic injects its h3 default; when present, honor it (e.g. h3,custom).
	// Mirrors hysteria1 (hysteria.go). The value was previously parsed-then-ignored.
	// (Audit 2026-06-26.)
	if alpn := getOneOfN(decoded, "", "alpn"); alpn != "" {
		h2opts.TLS.ALPN = strings.Split(alpn, ",")
	}

	// bandwidth hints (upmbps/downmbps) — v2rayN/Happ hy2 export extension.
	// Mirrors hysteria1; enables Brutal congestion control (SendBPS/ReceiveBPS).
	if upMbps := parseMbpsHint(getOneOfN(decoded, "", "upmbps", "up")); upMbps > 0 {
		h2opts.UpMbps = upMbps
	}
	if downMbps := parseMbpsHint(getOneOfN(decoded, "", "downmbps", "down")); downMbps > 0 {
		h2opts.DownMbps = downMbps
	}

	// port hopping — sing-box expects 'A:B'. Sources, in precedence order:
	//   1. native host range (host:A-B), lifted out before ParseUrl above
	//   2. mport/ports query param
	if hasHostPortRange {
		entries, _ := normalizeHopPorts(hostPortRange)
		h2opts.ServerPorts = badoption.Listable[string](entries)
	} else if mp := getOneOfN(decoded, "", "mport", "ports"); mp != "" {
		entries, _ := normalizeHopPorts(mp)
		h2opts.ServerPorts = badoption.Listable[string](entries)
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
