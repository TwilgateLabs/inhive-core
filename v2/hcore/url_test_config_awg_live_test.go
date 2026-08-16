//go:build with_awg

package hcore

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"testing"

	awgconn "github.com/amnezia-vpn/amneziawg-go/conn"
	awgdevice "github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"golang.org/x/crypto/curve25519"
)

// awgTestKeypair is a real Curve25519 keypair — the handshake MACs are derived
// from the public key, so unlike the crash reproducer this test needs keys that
// actually match.
type awgTestKeypair struct {
	private [32]byte
	public  [32]byte
}

func newAwgTestKeypair(t *testing.T) awgTestKeypair {
	t.Helper()
	var kp awgTestKeypair
	if _, err := rand.Read(kp.private[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	kp.private[0] &= 248
	kp.private[31] = (kp.private[31] & 127) | 64
	pub, err := curve25519.X25519(kp.private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("curve25519: %v", err)
	}
	copy(kp.public[:], pub)
	return kp
}

func (k awgTestKeypair) privateB64() string { return base64.StdEncoding.EncodeToString(k.private[:]) }
func (k awgTestKeypair) publicB64() string  { return base64.StdEncoding.EncodeToString(k.public[:]) }
func (k awgTestKeypair) privateHex() string { return hex.EncodeToString(k.private[:]) }
func (k awgTestKeypair) publicHex() string  { return hex.EncodeToString(k.public[:]) }

// awg obfuscation parameters shared by both sides of the live test — s1/s2
// (handshake padding) and h1..h4 (message-type headers) MUST match or the
// responder silently drops the initiation, which is exactly what makes this
// test prove the UAPI config is applied for real.
const (
	awgTestJc, awgTestJmin, awgTestJmax = 3, 8, 40
	awgTestS1, awgTestS2                = 17, 29
	awgTestH1, awgTestH2                = 123456701, 223456702
	awgTestH3, awgTestH4                = 323456703, 423456704
)

// startAwgTestResponder brings up a genuine amneziawg-go responder on a
// localhost UDP port with a netstack tun serving "HTTP 204" at serverIP:80
// inside the tunnel. Returns the UDP port it listens on.
func startAwgTestResponder(t *testing.T, server, client awgTestKeypair, serverIP, clientIP netip.Addr) uint16 {
	t.Helper()

	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{serverIP}, nil, 1408)
	if err != nil {
		t.Fatalf("responder netstack: %v", err)
	}
	logger := &awgdevice.Logger{Verbosef: awgdevice.DiscardLogf, Errorf: t.Logf}
	dev := awgdevice.NewDevice(tun, awgconn.NewDefaultBind(), logger)
	t.Cleanup(dev.Close)

	// Port 0 is not supported by UAPI listen_port semantics uniformly across
	// versions, so pick a free UDP port ourselves.
	probe, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	port := uint16(probe.LocalAddr().(*net.UDPAddr).Port)
	probe.Close()

	ipc := fmt.Sprintf(
		"private_key=%s\nlisten_port=%d\njc=%d\njmin=%d\njmax=%d\ns1=%d\ns2=%d\nh1=%d\nh2=%d\nh3=%d\nh4=%d\npublic_key=%s\nallowed_ip=%s/32\n",
		server.privateHex(), port,
		awgTestJc, awgTestJmin, awgTestJmax, awgTestS1, awgTestS2,
		awgTestH1, awgTestH2, awgTestH3, awgTestH4,
		client.publicHex(), clientIP,
	)
	if err := dev.IpcSet(ipc); err != nil {
		t.Fatalf("responder IpcSet: %v", err)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("responder up: %v", err)
	}

	listener, err := tnet.ListenTCP(&net.TCPAddr{IP: serverIP.AsSlice(), Port: 80})
	if err != nil {
		t.Fatalf("responder listener: %v", err)
	}
	t.Cleanup(func() { listener.Close() })
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	go srv.Serve(listener)
	t.Cleanup(func() { srv.Close() })

	return port
}

// TestUrlTestConfig_AwgEndpoint_Live is the acceptance test for the 2026-08-16
// AWG fix: the ping of a WORKING AmneziaWG server must go green. It proves the
// whole chain for real — endpoint Start actually starts the amneziawg device
// (the shadowed-Start bug left it nil forever), the bind dials with a live
// context, the junk/obfuscation params (jc/s1/s2/h1..h4) are applied via UAPI
// on both sides (a mismatch or a dropped param would fail the handshake), and
// the probe measures a genuine 204 THROUGH the tunnel.
func TestUrlTestConfig_AwgEndpoint_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up two userspace WG devices")
	}
	server := newAwgTestKeypair(t)
	client := newAwgTestKeypair(t)
	serverIP := netip.MustParseAddr("10.99.77.1")
	clientIP := netip.MustParseAddr("10.99.77.2")
	port := startAwgTestResponder(t, server, client, serverIP, clientIP)

	cfg := fmt.Sprintf(`{
  "endpoints": [
    {
      "type": "awg",
      "tag": "awg-live",
      "private_key": %q,
      "address": ["%s/32"],
      "jc": %d, "jmin": %d, "jmax": %d,
      "s1": %d, "s2": %d,
      "h1": "%d", "h2": "%d", "h3": "%d", "h4": "%d",
      "peers": [
        {
          "address": "127.0.0.1",
          "port": %d,
          "public_key": %q,
          "allowed_ips": ["0.0.0.0/0"],
          "persistent_keepalive_interval": 25
        }
      ]
    }
  ],
  "outbounds": [
    {"type": "selector", "tag": "select", "outbounds": ["awg-live", "direct"], "default": "awg-live"},
    {"type": "direct", "tag": "direct"},
    {"type": "block", "tag": "block"}
  ]
}`, client.privateB64(), clientIP,
		awgTestJc, awgTestJmin, awgTestJmax, awgTestS1, awgTestS2,
		awgTestH1, awgTestH2, awgTestH3, awgTestH4,
		port, server.publicB64())

	resp, err := (&CoreService{}).UrlTestConfig(context.Background(), &UrlTestConfigRequest{
		ConfigJson: cfg,
		// Probe by in-tunnel IP: no DNS involved, and the /generate_204 handler
		// returns exactly the 204 the strict status guard requires.
		Url:       fmt.Sprintf("http://%s/generate_204", serverIP),
		TimeoutMs: 10000,
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("ping through a live awg tunnel must succeed, got: bring_up=%v rejected=%v err=%s",
			resp.BringUpFailed, resp.ConfigRejected, resp.Error)
	}
	if resp.DelayMs <= 0 {
		t.Fatalf("expected positive delay, got %d", resp.DelayMs)
	}
	t.Logf("live awg tunnel ping: %d ms", resp.DelayMs)
}
