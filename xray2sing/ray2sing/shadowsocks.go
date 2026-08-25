package ray2sing

import (
	"encoding/base64"
	"fmt"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// ssSupportedMethods — exact allow-list of the sing-shadowsocks2 v0.2.1 method
// registry (cipher/method_none.go + shadowaead/method.go + shadowstream/method.go
// + shadowaead_2022/method.go). Sourced from the vendored dependency, NOT from
// mihomo's superset: a method outside this set errors "unknown method" at
// outbound creation and turns the node into an invalid stub, so it must be
// rejected here with a readable reason instead. Keep in sync on go.mod bumps.
var ssSupportedMethods = map[string]bool{
	"none":                          true,
	"aes-128-gcm":                   true,
	"aes-192-gcm":                   true,
	"aes-256-gcm":                   true,
	"chacha20-ietf-poly1305":        true,
	"xchacha20-ietf-poly1305":       true,
	"2022-blake3-aes-128-gcm":       true,
	"2022-blake3-aes-256-gcm":       true,
	"2022-blake3-chacha20-poly1305": true,
	"aes-128-ctr":                   true,
	"aes-192-ctr":                   true,
	"aes-256-ctr":                   true,
	"aes-128-cfb":                   true,
	"aes-192-cfb":                   true,
	"aes-256-cfb":                   true,
	"rc4-md5":                       true,
	"chacha20-ietf":                 true,
	"xchacha20":                     true,
}

// normalizeSSMethod canonicalizes foreign Shadowsocks cipher vocabulary
// (Xray/v2ray/shadowsocks-rust/Clash spellings) to the names sing-shadowsocks2
// registers. Sibling of normalizePacketEncoding. Unrecognized values pass
// through lowercased/trimmed only — an unsupported cipher must NOT be coerced
// to a default (that would silently downgrade encryption / break the
// handshake); it surfaces via the ssSupportedMethods check instead. Note: bare
// "chacha20" is deliberately NOT aliased to chacha20-ietf — different nonce
// size, not the same cipher.
func normalizeSSMethod(v string) string {
	m := strings.ToLower(strings.TrimSpace(v))
	switch m {
	case "dummy", "plain": // shadowsocks-rust / SIP002 aliases of "none"
		return "none"
	case "chacha20-poly1305": // Xray/v2ray alias, identical algorithm
		return "chacha20-ietf-poly1305"
	case "xchacha20-poly1305":
		return "xchacha20-ietf-poly1305"
	case "aead_aes_128_gcm": // v2ray legacy JSON spellings
		return "aes-128-gcm"
	case "aead_aes_192_gcm":
		return "aes-192-gcm"
	case "aead_aes_256_gcm":
		return "aes-256-gcm"
	case "aead_chacha20_poly1305":
		return "chacha20-ietf-poly1305"
	case "aead_xchacha20_poly1305":
		return "xchacha20-ietf-poly1305"
	default:
		return m
	}
}

// normalizeSS2022Password canonicalizes an SS2022 PSK (or ':'-chained PSK list
// for EIH) to std-base64: sing-shadowsocks2 does base64.StdEncoding.DecodeString
// per ':'-segment and errors on the url-safe '-'/'_' alphabet or missing
// padding, both of which panels emit inside URIs to avoid percent-encoding.
// Segments that already decode under std encoding are left untouched.
func normalizeSS2022Password(pass string) string {
	parts := strings.Split(pass, ":")
	for i, p := range parts {
		if _, err := base64.StdEncoding.DecodeString(p); err == nil {
			continue // already valid std base64 — do not corrupt it
		}
		p = strings.NewReplacer("-", "+", "_", "/").Replace(p)
		if m := len(p) % 4; m != 0 {
			p += strings.Repeat("=", 4-m)
		}
		parts[i] = p
	}
	return strings.Join(parts, ":")
}

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

	// sing-box's sip003 registry has exactly two plugins: obfs-local and
	// v2ray-plugin. Alias the foreign spellings real subscriptions carry
	// (simple-obfs project name, Clash's "obfs", the wire-compatible
	// xray-plugin fork); anything else would die as "plugin not found" at
	// outbound creation, so reject it here with a readable reason instead.
	plugin = strings.ToLower(plugin)
	switch plugin {
	case "", "obfs-local", "v2ray-plugin":
		// registered as-is / no plugin
	case "simple-obfs", "obfs":
		plugin = "obfs-local"
	case "xray-plugin":
		plugin = "v2ray-plugin"
	default:
		return nil, fmt.Errorf("shadowsocks plugin %q is not supported by the sing-box core", plugin)
	}

	method := normalizeSSMethod(defaultMethod)
	if !ssSupportedMethods[method] {
		return nil, fmt.Errorf("shadowsocks cipher %q is not supported by the sing-box core", defaultMethod)
	}
	if strings.HasPrefix(method, "2022-") && pass != "" {
		pass = normalizeSS2022Password(pass)
	}

	options := &T.ShadowsocksOutboundOptions{
		ServerOptions: u.GetServerOption(),
		Method:        method,
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
