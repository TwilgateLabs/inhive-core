package ray2sing

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// baseName strips the pipeline's global " § N" tag-uniquifier suffix
// (convert.go) and surrounding whitespace so tests compare the human node name.
func baseName(tag string) string {
	if i := strings.LastIndex(tag, " § "); i >= 0 {
		tag = tag[:i]
	}
	return strings.TrimSpace(tag)
}

// Happ exports a subscription as a JSON ARRAY where each element is a FULL Xray
// config object. The real node name lives in a top-level "remarks" field; the
// inner proxy outbound is always the generic tag "proxy". Two hazards this test
// pins down (all three were live bugs before the 2026-07-06 fix):
//
//	BUG 1 — remarks lost → every node showed as "proxy"/"proxy-2"/…
//	BUG 2 — hysteria2 (protocol:"hysteria", version 2) dropped as "not rebuilt"
//	BUG 3 — "Авто" bundles (which pack the whole node list as outbounds for
//	        client-side smart routing) exploded into dozens of duplicate "proxy"
//	        entries instead of collapsing to one node.

// happSample is a compact, representative Happ body: 3 countries × (TCP / gRPC /
// TROJAN), one Hysteria2 node, one "Авто" bundle that carries the whole list as
// outbounds, and one system "days-left" config. Mirrors the live xpnet shape.
const happSample = `[
  {"remarks":"📅 Осталось 151д.","dns":{"servers":[]},"routing":{"rules":[]},"outbounds":[
    {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"days.example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"days.example.com","publicKey":"PUBKEYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","shortId":"ab12","fingerprint":"chrome"}}},
    {"tag":"direct","protocol":"freedom"},
    {"tag":"block","protocol":"blackhole"}
  ]},
  {"remarks":"🇫🇲 🛜 Wi-Fi | Авто","routing":{"balancers":[{"tag":"b","selector":["proxy"]}]},"outbounds":[
    {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"auto1.example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"auto1.example.com","publicKey":"PUBKEYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","shortId":"ab12"}}},
    {"tag":"proxy-2","protocol":"vless","settings":{"vnext":[{"address":"auto2.example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"auto2.example.com","publicKey":"PUBKEYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","shortId":"ab12"}}},
    {"tag":"proxy-3","protocol":"trojan","settings":{"servers":[{"address":"auto3.example.com","port":443,"password":"PW"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"auto3.example.com"}}},
    {"tag":"direct","protocol":"freedom"},
    {"tag":"block","protocol":"blackhole"}
  ]},
  {"remarks":"🇳🇱 ♾️ Netherlands | TCP","outbounds":[
    {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"nl.example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"nl.example.com","publicKey":"PUBKEYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","shortId":"ab12"}}},
    {"tag":"direct","protocol":"freedom"},
    {"tag":"block","protocol":"blackhole"}
  ]},
  {"remarks":"🇳🇱 ♾️ Netherlands | gRPC","outbounds":[
    {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"nlg.example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","encryption":"none"}]}]},"streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"grpcpath"},"security":"reality","realitySettings":{"serverName":"nlg.example.com","publicKey":"PUBKEYaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","shortId":"ab12"}}},
    {"tag":"direct","protocol":"freedom"},
    {"tag":"block","protocol":"blackhole"}
  ]},
  {"remarks":"🇳🇱 ♾️ Netherlands | TROJAN","outbounds":[
    {"tag":"proxy","protocol":"trojan","settings":{"servers":[{"address":"nlt.example.com","port":443,"password":"TPW"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"nlt.example.com"}}},
    {"tag":"direct","protocol":"freedom"},
    {"tag":"block","protocol":"blackhole"}
  ]},
  {"remarks":"🇳🇱 ♾️🔥 Netherlands | Hysteria2","outbounds":[
    {"tag":"proxy","protocol":"hysteria","settings":{"address":"nlhy2.example.com","port":8449,"version":2},"streamSettings":{"network":"hysteria","hysteriaSettings":{"version":2,"auth":"cbe20af3-b60f-414a-83be-7d53b7a6b642"},"security":"tls","tlsSettings":{"serverName":"nlhy2.example.com","fingerprint":"chrome","alpn":["h3"]}}},
    {"tag":"direct","protocol":"freedom"},
    {"tag":"block","protocol":"blackhole"}
  ]}
]`

// TestHappJSONIngest is the inline contract test for the Happ per-node array.
func TestHappJSONIngest(t *testing.T) {
	opts, err := Ray2SingboxOptions(context.Background(), happSample, false)
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}

	// (a) exactly one node per config — no "Авто"-bundle duplicate explosion.
	// 6 configs in → 6 nodes out.
	if len(opts.Outbounds) != 6 {
		t.Fatalf("expected 6 nodes (one per config, Авто collapsed), got %d", len(opts.Outbounds))
	}

	wantNames := []string{
		"📅 Осталось 151д.",
		"🇫🇲 🛜 Wi-Fi | Авто",
		"🇳🇱 ♾️ Netherlands | TCP",
		"🇳🇱 ♾️ Netherlands | gRPC",
		"🇳🇱 ♾️ Netherlands | TROJAN",
		"🇳🇱 ♾️🔥 Netherlands | Hysteria2",
	}
	// (d) order preserved = array order.
	for i, ob := range opts.Outbounds {
		got := baseName(ob.Tag)
		// (a) names come from remarks, never the generic inner "proxy" tag.
		if strings.HasPrefix(got, "proxy") {
			t.Errorf("node %d kept generic inner tag %q — remarks not applied", i, got)
		}
		if got != wantNames[i] {
			t.Errorf("node %d: name/order mismatch\n got  %q\n want %q", i, got, wantNames[i])
		}
	}

	// (b) the Hysteria2 node survives (was dropped before the fix).
	hy2 := 0
	for _, ob := range opts.Outbounds {
		if ob.Type == "hysteria2" {
			hy2++
		}
	}
	if hy2 != 1 {
		t.Errorf("expected 1 hysteria2 node, got %d", hy2)
	}
}

// TestHappJSONIngestGolden replays the real captured xpnet Happ body (66 full
// configs) and pins the whole-list contract: 66 nodes in array order, real
// country names (never "proxy"), and all 11 Hysteria2 nodes present.
func TestHappJSONIngestGolden(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("testdata", "happ_xpnet.json"))
	if err != nil {
		t.Skipf("golden corpus missing: %v", err)
	}

	opts, err := Ray2SingboxOptions(context.Background(), string(body), false)
	if err != nil {
		t.Fatalf("ingest failed: %v", err)
	}

	if len(opts.Outbounds) != 66 {
		t.Fatalf("expected 66 nodes (one per config), got %d", len(opts.Outbounds))
	}

	hy2 := 0
	for i, ob := range opts.Outbounds {
		if strings.HasPrefix(baseName(ob.Tag), "proxy") {
			t.Errorf("node %d kept generic tag %q — remarks not applied", i, ob.Tag)
		}
		if ob.Type == "hysteria2" {
			hy2++
		}
	}
	if hy2 != 11 {
		t.Errorf("expected 11 hysteria2 nodes, got %d", hy2)
	}

	// Order spot-check: first three names in array order.
	wantHead := []string{"📅 Осталось 151д.", "🇫🇲 🛜 Wi-Fi | Авто", "🇫🇲 📶 LTE/4G | Авто"}
	for i, w := range wantHead {
		if got := baseName(opts.Outbounds[i].Tag); got != w {
			t.Errorf("head order mismatch at %d: got %q want %q", i, got, w)
		}
	}
	// Last node in the real file is a "Обход бел. списков #19" vless.
	if last := baseName(opts.Outbounds[65].Tag); !strings.Contains(last, "Обход бел. списков #19") {
		t.Errorf("tail order mismatch: last node %q", last)
	}
}
