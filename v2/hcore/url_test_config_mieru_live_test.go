package hcore

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	mieruconstant "github.com/enfein/mieru/v3/apis/constant"
	mierumodel "github.com/enfein/mieru/v3/apis/model"
	mieruserver "github.com/enfein/mieru/v3/apis/server"
	mierupb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"google.golang.org/protobuf/proto"
)

// startMieruTestResponder brings up a GENUINE mieru server (the same
// github.com/enfein/mieru library the production `mita` server runs) on a
// localhost TCP port. Accepted proxy connections are answered with the standard
// fake-SOCKS5 success and then piped to `allowedUpstream` — and ONLY there: any
// other destination is refused, which keeps the test hermetic by construction
// (nothing can escape the loopback even if the probe misbehaves).
//
// Returns the TCP port the mieru server listens on.
func startMieruTestResponder(t *testing.T, username, password, allowedUpstream string) uint16 {
	t.Helper()

	// The mieru server API has no listen-on-port-0 semantics (the port is part of
	// the config proto), so pick a free TCP port ourselves — same pattern as the
	// awg live test's UDP port probe.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	port := uint16(probe.Addr().(*net.TCPAddr).Port)
	probe.Close()

	intPort := int32(port)
	srv := mieruserver.NewServer()
	err = srv.Store(&mieruserver.ServerConfig{
		Config: &mierupb.ServerConfig{
			PortBindings: []*mierupb.PortBinding{
				{
					Port:     &intPort,
					Protocol: mierupb.TransportProtocol_TCP.Enum(),
				},
			},
			Users: []*mierupb.User{
				{
					Name:     proto.String(username),
					Password: proto.String(password),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("mieru server Store: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("mieru server Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	go func() {
		for {
			conn, request, err := srv.Accept()
			if err != nil {
				if !srv.IsRunning() {
					return
				}
				continue
			}
			go serveMieruTestConn(t, conn, request, allowedUpstream)
		}
	}()

	return port
}

// serveMieruTestConn mirrors the responder half of our sing-box mieru inbound
// (protocol/mieru/inbound.go handleConnection): fake SOCKS5 success first, then
// pipe the decrypted stream to the destination requested by the client.
func serveMieruTestConn(t *testing.T, conn net.Conn, request *mierumodel.Request, allowedUpstream string) {
	defer conn.Close()

	resp := &mierumodel.Response{
		Reply: mieruconstant.Socks5ReplySuccess,
		BindAddr: mierumodel.AddrSpec{
			IP:   net.IPv4zero,
			Port: 0,
		},
	}
	if err := resp.WriteToSocks5(conn); err != nil {
		return
	}
	if request.Command != mieruconstant.Socks5ConnectCmd {
		return
	}
	dst := request.DstAddr.String()
	if dst != allowedUpstream {
		// Hermetic guard: the responder never dials anything but the local
		// httptest server.
		t.Logf("mieru responder: refusing unexpected destination %s", dst)
		return
	}
	upstream, err := net.Dial("tcp", dst)
	if err != nil {
		return
	}
	defer upstream.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, conn)
		if tc, ok := upstream.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(conn, upstream)
	}()
	wg.Wait()
}

// TestUrlTestConfig_Mieru_Live is the liveness gate for the mieru outbound —
// the protocol every Wi-Fi user rides today. It proves the whole client chain
// for real and hermetically (loopback only, no internet):
//
//	config JSON → option.MieruOutboundOptions parse → registry → mieru client
//	Start → encrypted mieru handshake against a GENUINE enfein/mieru server →
//	SOCKS5-over-mieru CONNECT → HTTP 204 measured THROUGH the tunnel.
//
// A refactoring that silently breaks the mieru handshake, the client config
// mapping (buildMieruClientConfig) or the dialer plumbing turns this red in CI
// instead of surfacing as user reports.
func TestUrlTestConfig_Mieru_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up a userspace mieru server")
	}

	// In-tunnel target: local 204 endpoint. The probe requires exactly 204, so a
	// success is only reachable by genuinely traversing mieru → responder → here.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	targetAddr := target.Listener.Addr().String()

	const username, password = "inhive_test", "inhive_test_password"
	port := startMieruTestResponder(t, username, password, targetAddr)

	cfg := fmt.Sprintf(`{
  "outbounds": [
    {
      "type": "mieru",
      "tag": "mieru-live",
      "server": "127.0.0.1",
      "server_port": %d,
      "portBindings": [{"port": %d, "protocol": "TCP"}],
      "username": %q,
      "password": %q
    },
    {"type": "direct", "tag": "direct"}
  ]
}`, port, port, username, password)

	resp, err := (&CoreService{}).UrlTestConfig(context.Background(), &UrlTestConfigRequest{
		ConfigJson: cfg,
		Url:        "http://" + targetAddr + "/generate_204",
		TimeoutMs:  15000,
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("ping through a live mieru tunnel must succeed, got: bring_up=%v rejected=%v err=%s",
			resp.BringUpFailed, resp.ConfigRejected, resp.Error)
	}
	if resp.DelayMs <= 0 {
		t.Fatalf("expected positive delay, got %d", resp.DelayMs)
	}
	t.Logf("live mieru tunnel ping: %d ms", resp.DelayMs)
}
