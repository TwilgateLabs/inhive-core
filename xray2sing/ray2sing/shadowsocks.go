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
	// so the whole string must not be passed as the plugin name.
	plugin := decoded["plugin"]
	pluginOptions := ""
	if i := strings.Index(plugin, ";"); i >= 0 {
		pluginOptions = plugin[i+1:]
		plugin = plugin[:i]
	}

	result := T.Outbound{
		Type: "shadowsocks",
		Tag:  u.Name,
		Options: &T.ShadowsocksOutboundOptions{
			ServerOptions: u.GetServerOption(),
			Method:        defaultMethod,
			Password:      pass,
			Plugin:        plugin,
			PluginOptions: pluginOptions,
		},
	}

	return &result, nil
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
