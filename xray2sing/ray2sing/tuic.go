package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"strconv"
	"strings"
	"time"
)

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
	heartbeat := badoption.Duration(10 * time.Second)
	if hb := getOneOfN(decoded, "", "heartbeat"); hb != "" {
		if secs, err := strconv.Atoi(hb); err == nil {
			heartbeat = badoption.Duration(time.Duration(secs) * time.Second)
		} else if d, err := time.ParseDuration(hb); err == nil {
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
					DisableSNI: decoded["sni"] == "",
					ServerName: decoded["sni"],
					// getOneOfN normalizes both the lookup key and the variants, so the
					// underscore form allow_insecure (which normalizeStr turns into the
					// key "allow insecure") is matched too — a direct map["allowinsecure"]
					// lookup silently missed it and dropped the insecure flag. (Audit 2026-06-23.)
					Insecure: getOneOfN(decoded, "", "insecure", "allowinsecure", "allow_insecure") == "1",
					ALPN:     alpnList,
					ECH:      ECHOpts,
				},
			},
			// TurnRelay: turnRelay,
		},
	}

	return &result, nil
}
