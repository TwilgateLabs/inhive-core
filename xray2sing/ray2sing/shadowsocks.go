package ray2sing

import (
	"strings"

	T "github.com/sagernet/sing-box/option"
)

func ShadowsocksSingbox(shadowsocksUrl string) (*T.Outbound, error) {
	// Legacy whole-base64 form: ss://base64(method:password@host:port)[#name]
	// The userinfo/host body has no plaintext '@', so ParseUrl can't split it.
	// Decode the body first and rebuild a SIP002-style URI before parsing.
	if rebuilt, ok := normalizeLegacyShadowsocks(shadowsocksUrl); ok {
		shadowsocksUrl = rebuilt
	}

	u, err := ParseUrl(shadowsocksUrl, 443)
	if err != nil {
		return nil, err
	}

	decoded := u.Params

	defaultMethod := u.Username
	pass := u.Password
	if u.Password == "" {
		pass = u.Username
		defaultMethod = "none"
	}

	// SIP003 plugin: "name;opt1=v1;opt2=v2" — split name from options on first ';'.
	// sing-box registers the plugin by bare name ("obfs-local"/"v2ray-plugin"),
	// so the whole string must not be passed as the plugin name. SIP002 mandates
	// backslash-escaping of ; : = \ inside option values, so split on the first
	// UNESCAPED ';' to avoid truncating an opt value that legitimately contains
	// an escaped ';' (e.g. obfs-host=a\;b). sing-box's sip003 layer unescapes.
	plugin := decoded["plugin"]
	pluginOptions := ""
	if i := indexUnescaped(plugin, ';'); i >= 0 {
		pluginOptions = plugin[i+1:]
		plugin = plugin[:i]
	}

	options := &T.ShadowsocksOutboundOptions{
		ServerOptions: u.GetServerOption(),
		Method:        defaultMethod,
		Password:      pass,
		Plugin:        plugin,
		PluginOptions: pluginOptions,
	}

	// UDP-over-TCP: tunnel UDP over the TCP stream on explicit ?uot=1 (mirror
	// socks.go). uot-version selects v1/v2. The runtime gives UoT precedence
	// over multiplex and refuses to build both (outbound.go:65-71), so only
	// wire up multiplex when UoT is not enabled.
	if toBool(getOneOfN(decoded, "", "uot", "udp-over-tcp"), false) {
		options.UDPOverTCP = &T.UDPOverTCPOptions{
			Enabled: true,
			Version: uint8(toInt(getOneOfN(decoded, "", "uot-version"))),
		}
	} else {
		options.Multiplex = getMuxOptions(decoded)
	}

	result := T.Outbound{
		Type:    "shadowsocks",
		Tag:     u.Name,
		Options: options,
	}

	return &result, nil
}

// indexUnescaped returns the index of the first occurrence of sep in s that is
// not preceded by an odd run of backslashes (i.e. not backslash-escaped per
// SIP002), or -1 if there is none.
func indexUnescaped(s string, sep byte) int {
	backslashes := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			backslashes++
		case sep:
			if backslashes%2 == 0 {
				return i
			}
			backslashes = 0
		default:
			backslashes = 0
		}
	}
	return -1
}

// normalizeLegacyShadowsocks converts the legacy whole-base64 ss:// form
// (ss://base64(method:password@host:port)[?params][#name]) into the SIP002
// form (ss://method:password@host:port[?params][#name]) so ParseUrl can split
// userinfo/host. Returns (rebuilt, true) only when the body is a base64 blob
// without a plaintext '@' that decodes to a "method:password@host:port" shape.
func normalizeLegacyShadowsocks(raw string) (string, bool) {
	const prefix = "ss://"
	if !strings.HasPrefix(raw, prefix) {
		return raw, false
	}
	body := raw[len(prefix):]

	// Preserve trailing query/fragment, decode only the authority blob.
	tail := ""
	if i := strings.IndexAny(body, "?#"); i >= 0 {
		tail = body[i:]
		body = body[:i]
	}

	// SIP002 (already has plaintext '@') — nothing to do here.
	if strings.Contains(body, "@") {
		return raw, false
	}
	if body == "" || !isBase64CharsOnly(body) {
		return raw, false
	}

	decodedBody, err := decodeBase64IfNeeded(body)
	if err != nil || !strings.Contains(decodedBody, "@") || !strings.Contains(decodedBody, ":") {
		return raw, false
	}

	return prefix + decodedBody + tail, true
}
