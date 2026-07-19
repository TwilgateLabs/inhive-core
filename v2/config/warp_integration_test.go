package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"

	T "github.com/sagernet/sing-box/option"
	warpobf "github.com/sagernet/wireguard-go/warpobf"
)

// TestWARPFullConfig проверяет что Flutter builder строит правильный WG endpoint.
// Запуск: cd core && go test ./v2/config/ -run TestWARPFullConfig -v -timeout 120s
func TestWARPFullConfig(t *testing.T) {
	t.Log("=== Step 1: Generate WARP credentials ===")
	_, _, wgConfig, err := GenerateWarpInfo("", "", "")
	if err != nil {
		t.Fatalf("GenerateWarpInfo: %v", err)
	}
	t.Logf("IPv4: %s, IPv6: %s, ClientID: %q", wgConfig.LocalAddressIPv4, wgConfig.LocalAddressIPv6, wgConfig.ClientID)

	// Строим endpoint через canonical Go path
	noise := warpobf.NoiseOptions{}
	ep, err := GenerateWarpSingbox(*wgConfig, "162.159.192.1", 2408, &noise)
	if err != nil {
		t.Fatalf("GenerateWarpSingbox: %v", err)
	}
	opts, ok := ep.Options.(*T.WireGuardEndpointOptions)
	if !ok {
		t.Fatalf("Expected *WireGuardEndpointOptions, got %T", ep.Options)
	}

	t.Log("=== Step 2: Extract canonical values from Go-generated options ===")
	goIPv4Prefix := 0
	if len(opts.Address) > 0 {
		goIPv4Prefix = opts.Address[0].Bits()
	}
	t.Logf("Go MTU: %d (Flutter sets 1330)", opts.MTU)
	t.Logf("Go IPv4 prefix: /%d (Flutter sets /24)", goIPv4Prefix)
	if len(opts.Peers) > 0 {
		p := opts.Peers[0]
		t.Logf("Go Peer.PublicKey: %s", p.PublicKey)
		t.Logf("Go Peer.Reserved: %v", p.Reserved)
	}

	t.Log("=== Step 3: Decode ClientID reserved bytes (Flutter side) ===")
	clientID := wgConfig.ClientID
	reserved := decodeClientID(clientID)
	t.Logf("ClientID: %q → reserved: %v", clientID, reserved)

	// Compare with Go-generated reserved
	if len(opts.Peers) > 0 && len(opts.Peers[0].Reserved) >= 3 {
		goRes := []int{int(opts.Peers[0].Reserved[0]), int(opts.Peers[0].Reserved[1]), int(opts.Peers[0].Reserved[2])}
		t.Logf("Go reserved: %v, Flutter reserved: %v", goRes, reserved)
		if goRes[0] != reserved[0] || goRes[1] != reserved[1] || goRes[2] != reserved[2] {
			t.Errorf("MISMATCH! Go=%v Flutter=%v", goRes, reserved)
		} else {
			t.Log("✓ Reserved bytes match")
		}
	}

	t.Log("=== Step 4: Flutter-style JSON for comparison ===")
	flutterJSON := buildFlutterStyleEndpoint(wgConfig, reserved)
	b, _ := json.MarshalIndent(flutterJSON, "", "  ")
	t.Logf("Flutter endpoint JSON:\n%s", string(b))

	t.Log("=== Step 5: UDP reachability ===")
	conn, err := net.DialTimeout("udp", "162.159.192.1:2408", 3*time.Second)
	if err != nil {
		t.Errorf("UDP dial failed: %v", err)
	} else {
		conn.Close()
		t.Log("✓ UDP 162.159.192.1:2408 reachable")
	}

	fmt.Println()
	fmt.Println("===== CANONICAL VALUES FOR FLUTTER BUILDER =====")
	fmt.Printf("address:     [\"%s/24\", \"%s/128\"]\n", wgConfig.LocalAddressIPv4, wgConfig.LocalAddressIPv6)
	fmt.Printf("private_key: %s\n", wgConfig.PrivateKey)
	fmt.Printf("peer.address:     162.159.192.1\n")
	fmt.Printf("peer.port:        2408\n")
	fmt.Printf("peer.public_key:  %s\n", wgConfig.PeerPublicKey)
	fmt.Printf("peer.reserved:    %v\n", reserved)
	fmt.Printf("mtu:              1330 (Go uses %d)\n", opts.MTU)
}

func decodeClientID(clientID string) []int {
	var decoded []byte
	var err error
	// Try all base64 variants
	for _, fn := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		decoded, err = fn(clientID)
		if err == nil && len(decoded) > 0 {
			break
		}
	}
	if len(decoded) < 3 {
		return []int{0, 0, 0}
	}
	return []int{int(decoded[0]), int(decoded[1]), int(decoded[2])}
}

func buildFlutterStyleEndpoint(wgConfig *WarpWireguardConfig, reserved []int) map[string]interface{} {
	return map[string]interface{}{
		"type":        "wireguard",
		"tag":         "warp-fallback",
		"address":     []string{wgConfig.LocalAddressIPv4 + "/24", wgConfig.LocalAddressIPv6 + "/128"},
		"private_key": wgConfig.PrivateKey,
		"mtu":         1330,
		"peers": []map[string]interface{}{
			{
				"address":                       "162.159.192.1",
				"port":                          2408,
				"public_key":                    wgConfig.PeerPublicKey,
				"allowed_ips":                   []string{"0.0.0.0/0", "::/0"},
				"reserved":                      reserved,
				"persistent_keepalive_interval": 25,
			},
		},
	}
}
