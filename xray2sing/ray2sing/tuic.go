package ray2sing

import (
	"fmt"
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"strconv"
	"strings"
	"time"
)

// looksLikeUUID — грубая форма-проверка v5-идентификатора (8-4-4-4-12 hex).
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
				return false
			}
		}
	}
	return true
}

func TuicSingbox(tuicUrl string) (*T.Outbound, error) {
	u, err := ParseUrl(tuicUrl, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	valECH, hasECH := decoded["ech"]
	hasECH = hasECH && (valECH != "0")
	var ECHOpts *T.OutboundECHOptions
	ECHOpts = nil
	if hasECH {
		ECHOpts = &T.OutboundECHOptions{
			Enabled: hasECH,
		}
	}
	// turnRelay, err := ParseTurnURL(decoded["relay"])
	// if err != nil {
	// 	return nil, err
	// }

	// ALPN: read from the URI when present (csv), nil when absent.
	// Do NOT re-inject the legacy hiddify-core ["h3","spdy/3.1"] default —
	// sing-box's empty-ALPN default is correct for TUIC.
	var alpnList []string
	if alpn := getOneOfN(decoded, "", "alpn"); alpn != "" {
		alpnList = strings.Split(alpn, ",")
	}

	// Heartbeat: read from the URI when present, default 10s (matches sing-box).
	// Only accept a STRICTLY POSITIVE result: sing-quic's client special-cases
	// only ==0, so a negative value (heartbeat=-1 passes Atoi cleanly) or an
	// int64 overflow-to-negative (secs>=~9.3e9, e.g. milliseconds pasted as
	// seconds) reaches time.NewTicker in a bare dial goroutine, which PANICS on
	// d<=0 and crashes the whole process — no recover covers it.
	heartbeat := badoption.Duration(10 * time.Second)
	if hb := getOneOfN(decoded, "", "heartbeat"); hb != "" {
		if secs, err := strconv.Atoi(hb); err == nil {
			if d := time.Duration(secs) * time.Second; secs > 0 && d > 0 {
				heartbeat = badoption.Duration(d)
			}
		} else if d, err := time.ParseDuration(hb); err == nil && d > 0 {
			heartbeat = badoption.Duration(d)
		}
	}

	// udp_over_stream and udp_relay_mode are mutually exclusive in the
	// transport (protocol/tuic/outbound.go errors if both are set), so when
	// udp_over_stream is enabled we leave udp_relay_mode empty.
	udpOverStream := toBool(getOneOfN(decoded, "", "udp_over_stream"), false)
	udpRelayMode := ""
	if !udpOverStream {
		udpRelayMode = getOneOfN(decoded, "", "udp_relay_mode", "udprelaymode")
	}

	// SNI: explicit sni= wins; otherwise fall back to the connect host so a hostname
	// endpoint still sends SNI (matches Happ) and keeps TLS cert verification. Only a
	// bare-IP server legitimately omits SNI (isIPOnly → disable_sni), exactly like
	// hysteria2.go. The old `DisableSNI: decoded["sni"]==""` force-disabled SNI for
	// EVERY hostname endpoint without an explicit sni= — breaking SNI-routed fronts
	// AND silently dropping cert verification. (Audit 2026-06-26.)
	sni := decoded["sni"]
	if sni == "" {
		sni = u.Hostname
	}
	// disable_sni=1 из ссылки (sing-box/NekoBox словарь): раньше параметр не
	// читался вовсе и мы ОТПРАВЛЯЛИ SNI, который ссылка просила не слать.
	disableSNI := toBool(getOneOfN(decoded, "", "disable_sni", "disablesni"), false) || isIPOnly(sni)

	// Легаси tuic v4 (tuic://TOKEN@host?version=4): у v5-ядра sing-box токен
	// не UUID — нода молча умирала на uuid.FromString при создании.
	if getOneOfN(decoded, "", "version") == "4" || !looksLikeUUID(u.Username) {
		return nil, fmt.Errorf("tuic v4 token links are not supported by the sing-box core (v5 uuid:password required)")
	}

	result := T.Outbound{
		Type: "tuic",
		Tag:  u.Name,
		Options: &T.TUICOutboundOptions{
			ServerOptions:     u.GetServerOption(),
			UUID:              u.Username,
			Password:          u.Password,
			CongestionControl: getOneOfN(decoded, "", "congestion_control", "congestioncontrol"),
			UDPRelayMode:      udpRelayMode,
			UDPOverStream:     udpOverStream,
			ZeroRTTHandshake:  toBool(getOneOfN(decoded, "", "zero_rtt_handshake", "zero_rtt", "0rtt"), false),
			Heartbeat:         heartbeat,
			OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
				TLS: &T.OutboundTLSOptions{
					Enabled:    true,
					DisableSNI: disableSNI,
					ServerName: sni,
					// getOneOfN normalizes both the lookup key and the variants, so the
					// underscore form allow_insecure (which normalizeStr turns into the
					// key "allow insecure") is matched too — a direct map["allowinsecure"]
					// lookup silently missed it and dropped the insecure flag. (Audit 2026-06-23.)
					Insecure: toBool(getOneOfN(decoded, "", "insecure", "allowinsecure", "allow_insecure"), false),
					ALPN:     alpnList,
					ECH:      ECHOpts,
				},
			},
			// TurnRelay: turnRelay,
		},
	}

	return &result, nil
}
