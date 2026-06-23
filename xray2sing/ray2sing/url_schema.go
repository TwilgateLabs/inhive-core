package ray2sing

import (
	"net/url"
	"regexp"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// HysteriaURLData holds the parsed data from a Hysteria URL.
type UrlSchema struct {
	Scheme   string
	Username string
	Password string
	Hostname string
	Port     uint16
	Name     string
	Params   map[string]string
}

func (u UrlSchema) GetServerOption() T.ServerOptions {
	return T.ServerOptions{
		Server:     u.Hostname,
		ServerPort: u.Port,
	}
}

// func (u UrlSchema) GetRelayOptions() (*T.TurnRelayOptions, error) {
// 	return ParseTurnURL(u.Params["relay"])
// }

// parseHysteria2 parses a given URL and returns a HysteriaURLData struct.
func ParseUrl(inputURL string, defaultPort uint16) (*UrlSchema, error) {
	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return nil, err
	}
	port := toUInt16(parsedURL.Port(), defaultPort)

	data := &UrlSchema{
		Scheme:   parsedURL.Scheme,
		Username: parsedURL.User.Username(),
		Password: getPassword(parsedURL),
		Hostname: parsedURL.Hostname(),
		Port:     port,
		Name:     parsedURL.Fragment,
		Params:   make(map[string]string),
	}
	// The base64 "method:password" userinfo form is SIP002 (shadowsocks) only.
	// For trojan/vless the userinfo is the password / UUID as a whole and may
	// legitimately be pure base64 charset (e.g. "YTpi" decodes to "a:b"), so
	// splitting it there destroys real credentials. Gate the heuristic on ss://.
	if data.Scheme == "ss" && isBase64CharsOnly(data.Username) {
		userInfo, err := decodeBase64IfNeeded(data.Username)

		// fmt.Print(userInfo)
		if err == nil && isValidChar(userInfo) {
			// Split on the FIRST colon only: SS-2022 (2022-blake3-*) passwords are
			// themselves base64 and contain ':' (method:uPSK:iPSK, or a single PSK
			// with '/' '+' '='), so strings.Split + len==2 dropped the whole decode
			// → method silently became "none". SplitN(2) keeps method = part[0],
			// password = everything after the first ':'. (Audit 2026-06-23.)
			userDetails := strings.SplitN(userInfo, ":", 2)
			if len(userDetails) == 2 {
				data.Username = userDetails[0]
				data.Password = userDetails[1]
			}
		}
	}

	for key, values := range parsedURL.Query() {
		data.Params[normalizeStr(key)] = strings.Join(values, ",")
	}

	// parsedURL.Query() follows HTML-form semantics and turns '+' into a space.
	// Reality keys (pbk/sid/spx) are standard base64 where '+' is significant,
	// and many panels emit them non-url-safe. Re-read those from the raw query
	// with PathUnescape (which decodes %XX but keeps '+' literal) so the public
	// key/short id survive intact.
	overrideRawQueryParams(data.Params, parsedURL.RawQuery, "pbk", "sid", "spx")

	return data, nil
}

// overrideRawQueryParams re-reads the listed query keys straight from the raw
// query string, preserving literal '+' (unlike url.Values which maps it to a
// space). Used for base64-valued params where '+' is part of the alphabet.
func overrideRawQueryParams(params map[string]string, rawQuery string, keys ...string) {
	if rawQuery == "" {
		return
	}
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[normalizeStr(k)] = true
	}
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq < 0 {
			continue
		}
		rawKey, rawVal := pair[:eq], pair[eq+1:]
		key, err := url.PathUnescape(rawKey)
		if err != nil {
			key = rawKey
		}
		nKey := normalizeStr(key)
		if !want[nKey] {
			continue
		}
		// PathUnescape decodes %XX but leaves '+' untouched.
		val, err := url.PathUnescape(rawVal)
		if err != nil {
			val = rawVal
		}
		params[nKey] = val
	}
}

func normalizeStr(ss string) string {
	s := strings.ToLower(strings.TrimSpace(ss))
	for _, r := range []string{"_", "-"} {
		s = strings.ReplaceAll(s, r, " ")

	}
	return s
}

func getPassword(u *url.URL) string {
	if password, ok := u.User.Password(); ok {
		return password
	}
	return ""
}

var base64CharRegex = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

func isBase64CharsOnly(s string) bool {
	return base64CharRegex.MatchString(s)
}

var validCharRegex = regexp.MustCompile(`^[A-Za-z0-9+/=_)(: !~@#$%^&*-]+$`)

func isValidChar(s string) bool {

	return validCharRegex.MatchString(s)
}
