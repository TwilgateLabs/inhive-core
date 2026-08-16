//go:build with_awg

package hcore

import (
	"context"
	"testing"
)

// awgPingTestConfig mirrors the exact config shape the app produces for an
// imported AmneziaWG .conf (xray2sing canonicalization → singbox_config_builder):
// one awg ENDPOINT (sing-box 1.13 moved wireguard/awg to endpoints[]) with the
// AWG obfuscation fields (jc/jmin/jmax/s1/s2/h1..h4), a selector + direct/block
// in outbounds[], and the app's DoH DNS fan. Keys are freshly generated fakes;
// the peer endpoint points at localhost with nothing listening, so the probe
// must fail HONESTLY (tested-dead or bring-up error) — never kill the process.
const awgPingTestConfig = `{
  "dns": {
    "servers": [{"tag": "dns-direct", "type": "https", "server": "1.1.1.1", "detour": "direct"}],
    "final": "dns-direct"
  },
  "endpoints": [
    {
      "type": "awg",
      "tag": "awg-test",
      "private_key": "mA+M0r7CgC0cUQ4irKyO/fuGTDtt2/buYbHVY0SWWkE=",
      "address": ["10.8.1.26/32"],
      "jc": 4, "jmin": 10, "jmax": 50,
      "s1": 121, "s2": 126,
      "h1": "223127635", "h2": "112176701", "h3": "1712411879", "h4": "2044932059",
      "peers": [
        {
          "address": "127.0.0.1",
          "port": 44444,
          "public_key": "rdiCME73RQ+pEq8u6ZdLnqH40DxpIMV0VD2y9ZUHvNw=",
          "allowed_ips": ["0.0.0.0/0", "::/0"],
          "persistent_keepalive_interval": 25
        }
      ]
    }
  ],
  "outbounds": [
    {"type": "selector", "tag": "select", "outbounds": ["awg-test", "direct"], "default": "awg-test"},
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ]
}`

// TestUrlTestConfig_AwgEndpoint reproduces the 2026-08-16 field crash: pinging
// an imported AmneziaWG config made the whole Windows app vanish — a Go panic
// in a device goroutine that no gRPC-boundary recover can catch. The ping of an
// unreachable awg endpoint must complete as a soft failure (Error set), with
// the process alive. If this test crashes the test binary, THAT is the bug.
func TestUrlTestConfig_AwgEndpoint(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up a side-instance")
	}
	resp, err := (&CoreService{}).UrlTestConfig(context.Background(), &UrlTestConfigRequest{
		ConfigJson: awgPingTestConfig,
		TimeoutMs:  4000,
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp.Error == "" {
		t.Fatalf("unreachable awg peer must not ping green, got delay=%d", resp.DelayMs)
	}
	t.Logf("awg endpoint ping failed softly (as it must): bring_up=%v rejected=%v err=%s",
		resp.BringUpFailed, resp.ConfigRejected, resp.Error)
}
