package ray2sing_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/twilgate/xray2sing/ray2sing"
)

// alpnFor parses a share URI through ray2sing and returns the produced
// tls.alpn for the first outbound, normalized to a comma-joined string
// ("" if no TLS / no alpn). Used to assert per-transport ALPN clamping.
func alpnFor(t *testing.T, uri string) string {
	t.Helper()
	out, err := ray2sing.Ray2Singbox(context.Background(), uri, false)
	if err != nil {
		t.Fatalf("Ray2Singbox(%q): %v", uri, err)
	}
	var doc struct {
		Outbounds []struct {
			TLS *struct {
				ALPN any `json:"alpn"`
			} `json:"tls"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("unmarshal produced config: %v\n%s", err, out)
	}
	if len(doc.Outbounds) == 0 || doc.Outbounds[0].TLS == nil {
		return ""
	}
	switch v := doc.Outbounds[0].TLS.ALPN.(type) {
	case nil:
		return ""
	case string:
		return v
	case []any:
		parts := make([]string, 0, len(v))
		for _, p := range v {
			parts = append(parts, p.(string))
		}
		return strings.Join(parts, ",")
	default:
		t.Fatalf("unexpected alpn type %T: %v", v, v)
		return ""
	}
}

// TestALPNClampPerTransport locks in the 2026-06-26 root fix: ALPN must match
// the transport's HTTP version, regardless of what the subscription URI declares.
// HTTP/1.1-based transports (ws, httpupgrade) MUST NOT offer "h2" — the server can
// pick h2 at TLS-time and the HTTP/1.1 Upgrade then dies with EOF (the foreign-sub
// "Обход" bug: vless+ws alpn=http/1.1,h2 worked in Happ, EOF'd in our client).
// HTTP/2-based transports (grpc, h2) negotiate h2. This is a COMPATIBILITY invariant:
// every config class that works in Happ/Xray must work here.
func TestALPNClampPerTransport(t *testing.T) {
	const uuid = "00000000-0000-0000-0000-000000000000"
	cases := []struct {
		name string
		uri  string
		want string
	}{
		{
			// The exact bug shape: user-declared alpn includes h2 on a ws transport.
			"ws_drops_h2",
			"vless://" + uuid + "@cdn.example.icu:443?type=ws&security=tls&sni=cdn.example.icu&alpn=http%2F1.1%2Ch2&fp=chrome&path=%2Fstart&host=cdn.example.icu#ws_h2",
			"http/1.1",
		},
		{
			// ws with NO alpn declared must still clamp to http/1.1 (getTransportOptions
			// defaults decoded[alpn]=http/1.1, which getTLSOptions then must not re-pollute).
			"ws_no_alpn",
			"vless://" + uuid + "@cdn.example.icu:443?type=ws&security=tls&sni=cdn.example.icu&fp=chrome&path=%2Fstart&host=cdn.example.icu#ws_plain",
			"http/1.1",
		},
		{
			// httpupgrade is also an HTTP/1.1 upgrade — must drop h2.
			"httpupgrade_drops_h2",
			"vless://" + uuid + "@cdn.example.icu:443?type=httpupgrade&security=tls&sni=cdn.example.icu&alpn=http%2F1.1%2Ch2&fp=chrome&path=%2Fup&host=cdn.example.icu#hu_h2",
			"http/1.1",
		},
		{
			// gRPC runs over HTTP/2 — ALPN must be h2 (not h2,http/1.1 fallback).
			"grpc_is_h2",
			"vless://" + uuid + "@cdn.example.icu:443?type=grpc&security=tls&sni=cdn.example.icu&alpn=http%2F1.1%2Ch2&fp=chrome&serviceName=gs#grpc",
			"h2",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := alpnFor(t, c.uri)
			if got != c.want {
				t.Errorf("transport %s: alpn = %q, want %q (Happ-working config would break otherwise)", c.name, got, c.want)
			}
		})
	}
}
