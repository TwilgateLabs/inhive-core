package ray2sing

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"

	"encoding/json"
)

func decodeVmess(vmessConfig string) (map[string]string, error) {
	// Strip the scheme scheme-agnostically: the dispatch table also registers
	// this parser for svmess:// and xvmess:// (9 chars), so a hardcoded [8:]
	// left a leading '/' in the base64 body and silently lost every such link.
	vmessData := vmessConfig
	if i := strings.Index(vmessConfig, "://"); i >= 0 {
		vmessData = vmessConfig[i+3:]
	}
	// The body is an opaque base64 blob with no native fragment support, but
	// both real-world exporters (sing-box/Streisand style vmess://<b64>#name)
	// and our own Happ per-node rename (renameURIFragment in json_ingest.go)
	// append '#<name>' — which is not legal base64. Split it off before
	// decoding and let it override "ps" as the display name.
	body, frag, hasFrag := strings.Cut(vmessData, "#")
	// Обе URI-формы vmess несут ?query, которого у base64-JSON не бывает —
	// отрезаем до декода (иначе декодился body+query и падал).
	b64Part, _, _ := strings.Cut(body, "?")
	decodedData, err := decodeBase64FaultTolerant(b64Part)
	if err == nil && strings.HasPrefix(strings.TrimSpace(decodedData), "{") {
		var data map[string]interface{}
		jerr := json.Unmarshal([]byte(decodedData), &data)
		if jerr != nil {
			// Висячая запятая перед } / ] — шаблонизаторы кривых панелей.
			retry := trailingCommaRe.ReplaceAllString(decodedData, "$1")
			if jerr2 := json.Unmarshal([]byte(retry), &data); jerr2 != nil {
				return nil, jerr
			}
		}
		strdata := convertToStrings(data)
		normalizeVmessJSONFields(strdata)
		if hasFrag {
			if name, err := url.QueryUnescape(frag); err == nil && name != "" {
				strdata["ps"] = name
			}
		}
		return strdata, nil
	}
	// Не-JSON тело: две живые URI-формы —
	//  • v2fly VMessAEAD sharing: vmess://uuid@host:port?type=tcp&security=tls#name
	//    (тело вообще не base64 — '@' в нём нелегален);
	//  • Shadowrocket: vmess://BASE64(method:uuid@host:port)?remarks=..&obfs=websocket&tls=1
	// Обе раньше молча теряли ноду («illegal base64» / не-JSON).
	rebuilt := "vmess://"
	if err == nil && strings.Contains(decodedData, "@") {
		rebuilt += decodedData
		if q, ok := strings.CutPrefix(body, b64Part); ok && q != "" {
			rebuilt += q
		}
	} else if strings.Contains(body, "@") {
		rebuilt += body
	} else {
		if err != nil {
			return nil, err
		}
		return nil, E.New("vmess body is neither base64 JSON nor a URI form")
	}
	if hasFrag {
		rebuilt += "#" + frag
	}
	return decodeVmessURIForm(rebuilt)
}

// trailingCommaRe — ", }"/", ]" из шаблонизаторов панелей.
var trailingCommaRe = regexp.MustCompile(`,\s*([}\]])`)

// normalizeVmessJSONFields — толерантность к живым генераторам base64-JSON:
// bool/строковые булевы у tls, ключи в неканоничном регистре ("Host"),
// пробелы вокруг id (копипаст). Всё — silent-mangle классы из sweep 2026-09-02.
func normalizeVmessJSONFields(d map[string]string) {
	for k, v := range d {
		lk := strings.ToLower(k)
		if lk != k {
			if _, ok := d[lk]; !ok {
				d[lk] = v
			}
		}
	}
	switch strings.ToLower(strings.TrimSpace(d["tls"])) {
	case "true", "1":
		d["tls"] = "tls"
	}
	d["id"] = strings.TrimSpace(d["id"])
}

// decodeVmessURIForm разбирает URI-формы vmess через общий ParseUrl и мапит
// их словарь на ключи vmess-JSON, которых ждёт VmessSingbox.
func decodeVmessURIForm(rebuilt string) (map[string]string, error) {
	u, err := ParseUrl(rebuilt, 443)
	if err != nil {
		return nil, err
	}
	d := map[string]string{}
	for k, v := range u.Params {
		d[k] = v
	}
	// userinfo: "uuid" (AEAD) либо "method:uuid" (Shadowrocket).
	id := u.Username
	if u.Password != "" {
		if d["scy"] == "" {
			d["scy"] = u.Username
		}
		id = u.Password
	}
	d["id"] = strings.TrimSpace(id)
	d["add"] = u.Hostname
	d["port"] = strconv.Itoa(int(u.Port))
	if u.Name != "" {
		d["ps"] = u.Name
	} else if d["remarks"] != "" {
		d["ps"] = d["remarks"]
	}
	// AEAD-словарь → vmess-JSON словарь.
	if v := d["encryption"]; v != "" && d["scy"] == "" {
		d["scy"] = v
	}
	if v := d["security"]; v == "tls" || v == "reality" {
		d["tls"] = v
	}
	switch strings.ToLower(d["tls"]) { // Shadowrocket tls=1/true
	case "1", "true":
		d["tls"] = "tls"
	}
	// Shadowrocket: obfs=websocket/http/none (+obfsParam=Host, peer=SNI).
	switch strings.ToLower(d["obfs"]) {
	case "websocket", "ws":
		d["net"] = "ws"
	case "http":
		d["net"] = "tcp"
		d["type"] = "http"
	case "none":
		if d["net"] == "" {
			d["net"] = "tcp"
		}
	}
	if v := d["obfsparam"]; v != "" && d["host"] == "" {
		d["host"] = v
	}
	if v := d["alterid"]; v != "" && d["aid"] == "" {
		d["aid"] = v
	}
	if v := d["allowinsecure"]; v != "" && d["insecure"] == "" {
		d["insecure"] = v
	}
	return d, nil
}

// normalizeVmessSecurity maps foreign vmess "scy" vocabulary onto the set the
// (upstream) sing-vmess dependency accepts, which is an exact case-sensitive
// switch over {auto, none, zero, aes-128-cfb, aes-128-gcm, chacha20-poly1305}
// (sing-vmess client.go:36-55) — anything else kills the node at outbound
// creation. Unknown/legacy values fall back to "auto" (Xray parity: the client
// then negotiates a supported cipher) rather than passing through.
func normalizeVmessSecurity(scy string) string {
	s := strings.ToLower(strings.TrimSpace(scy))
	if s == "chacha20-ietf-poly1305" { // ss-spelling emitted by sloppy panels
		s = "chacha20-poly1305"
	}
	switch s {
	case "auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305":
		return s
	default: // "", uppercase variants already lowered above; anything else -> auto
		return "auto"
	}
}

func convertToStrings(data map[string]interface{}) map[string]string {
	stringMap := make(map[string]string)
	for key, value := range data {
		switch v := value.(type) {
		case string:
			stringMap[key] = v
		case float64:
			stringMap[key] = strconv.Itoa(int(v))
		case bool:
			if v {
				stringMap[key] = "true"
			} else {
				stringMap[key] = "false"
			}
		case []interface{}:
			// JSON-native генераторы шлют alpn массивом; fmt.Sprintf давал
			// "[h2 http/1.1]" — мусор на проводе. Склеиваем запятой, как в URI.
			parts := make([]string, 0, len(v))
			for _, e := range v {
				parts = append(parts, fmt.Sprintf("%v", e))
			}
			stringMap[key] = strings.Join(parts, ",")
		// case map[string]interface{}:
		// 	stringMap[key] = convertToStrings(v)

		default:
			stringMap[key] = fmt.Sprintf("%v", v)
		}
	}
	return stringMap

}

func VmessSingbox(vmessURL string) (*T.Outbound, error) {
	decoded, err := decodeVmess(vmessURL)
	if err != nil {
		return nil, err
	}

	port := toUInt16(decoded["port"], 443)
	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}
	security := normalizeVmessSecurity(decoded["scy"])
	// Leave PacketEncoding empty (upstream/runtime default = disabled) unless the
	// subscription carries an explicit hint. Forcing xudp on a server without XUDP
	// support can silently mishandle UDP-associated traffic.
	packetEncoding := normalizePacketEncoding(decoded["packetEncoding"])
	// vmess base64 JSON carries no fingerprint field; default to chrome so the
	// TLS ClientHello isn't the trivially-detectable Go-default stack (DPI).
	if decoded["tls"] == "tls" && decoded["fp"] == "" {
		decoded["fp"] = "chrome"
	}
	return &T.Outbound{
		Tag:  decoded["ps"],
		Type: "vmess",
		Options: &T.VMessOutboundOptions{
			DialerOptions: getDialerOptions(decoded),
			ServerOptions: T.ServerOptions{
				Server:     decoded["add"],
				ServerPort: port,
			},
			UUID:          decoded["id"],
			Security:      security,
			AlterId:       toInt(decoded["aid"]),
			GlobalPadding: false,
			// Default false (upstream parity); no standard vmess base64 field
			// signals it, and runtime negotiates the bit on the wire. Only set
			// true on an explicit hint to stay safe on legacy non-TLS AEAD nodes.
			AuthenticatedLength:         decoded["authenticatedLength"] == "true",
			PacketEncoding:              packetEncoding,
			OutboundTLSOptionsContainer: getTLSOptions(decoded),
			Transport:                   transportOptions,
			Multiplex:                   getMuxOptions(decoded),
		},
	}, nil
}
