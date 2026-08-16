//go:build with_olcrtc

package hcore

import (
	"context"
	"strings"
	"testing"
)

// TestUrlTestConfig_Olcrtc_Registered proves the with_olcrtc wiring end-to-end
// at the level the app uses it: config JSON parse → registry → REAL olcrtc
// outbound constructed and brought up inside a side-instance (lazy non-primary
// Start — zero network). If someone drops with_olcrtc from the include wiring
// or breaks option registration, the stub constructor answers "not included in
// this build" / config_rejected — and this test goes red.
//
// Hermetic by construction: every address in the config is loopback
// (room URL and DNS server point at 127.0.0.1:1), so the probe's join attempt
// fails fast WITHOUT any network egress. The probe failing is EXPECTED — the
// assertion is that the failure is a join failure of a real outbound, never a
// registry rejection. The actual traffic gate for the adapter plumbing lives in
// protocol/olcrtc/outbound_test.go (see its honest-scope note: the WebRTC link
// itself needs a live SFU and is out of hermetic reach from this module).
func TestUrlTestConfig_Olcrtc_Registered(t *testing.T) {
	cfg := `{
  "outbounds": [
    {
      "type": "olcrtc",
      "tag": "olcrtc-live",
      "carrier": "jitsi",
      "room_url": "https://127.0.0.1:1/room",
      "channel_id": "12345678-1234-4123-8123-123456789abc",
      "key_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      "dns_server": "127.0.0.1:1"
    },
    {"type": "direct", "tag": "direct"}
  ]
}`
	resp, err := (&CoreService{}).UrlTestConfig(context.Background(), &UrlTestConfigRequest{
		ConfigJson: cfg,
		Url:        "http://127.0.0.1:1/generate_204",
		TimeoutMs:  3000,
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if strings.Contains(resp.Error, "not included in this build") {
		t.Fatalf("olcrtc resolved to the STUB constructor — with_olcrtc include wiring is broken: %s", resp.Error)
	}
	if resp.ConfigRejected {
		t.Fatalf("olcrtc config must parse and bring up (lazy), got config_rejected: %s", resp.Error)
	}
	// The join attempt against loopback:1 must fail — a success here would mean
	// the probe measured something other than the olcrtc outbound.
	if resp.Error == "" {
		t.Fatalf("probe through an unjoinable olcrtc outbound must fail, got delay=%d", resp.DelayMs)
	}
	t.Logf("olcrtc registered; expected join failure: %s", resp.Error)
}
