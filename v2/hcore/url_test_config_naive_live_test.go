//go:build with_naive_outbound

package hcore

// Hermetic liveness gate for the naive outbound (protocol/naive + the embedded
// cronet/Chromium engine). This is the ONLY test that actually drives libcronet:
// the compiler knows nothing about the engine's runtime behavior (`go build` is
// always green — see the 4.7.0 libcronet incident), so "compiles" proves
// nothing here. The gate brings up a genuine naive INBOUND (upstream sing-box
// server implementation) in a side-instance and pushes a real HTTP probe
// through the cronet-backed outbound over loopback.
//
// Platform note: this file is tag-gated (with_naive_outbound). On the linux CI
// runner test binaries are built WITHOUT this tag (GNU ld rejects libcronet.a —
// see .github/workflows/build.yml "Resolve tags and packages"), so the gate
// runs in the dedicated macOS job (naive-live) and on dev machines, where
// cronet links statically via CGO.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// naiveTestCertificates generates a throwaway CA and a leaf certificate for
// `domain`, returning PEM strings (CA for the client's trusted roots, leaf
// cert+key for the naive inbound). RSA 2048 — mirrors the upstream
// sing-box naive self-test; cronet's verifier accepts it as a custom root.
func naiveTestCertificates(t *testing.T, domain string) (caPEM, certPEM, keyPEM string) {
	t.Helper()

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{Organization: []string{"inhive naive live-test CA"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{Organization: []string{"inhive naive live-test leaf"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{domain},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caTpl, leafKey.Public(), caKey)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}

	caPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}))
	return caPEM, certPEM, keyPEM
}

// startNaiveTestServer brings up a genuine naive server (upstream sing-box
// naive inbound, h2-over-TLS) in a side-instance whose only exit is `direct` —
// tunnelled CONNECTs land back on loopback. Returns the TLS listen port.
// RunInstanceRaw's sanitizer assigns the loopback port itself (the inbound is a
// ListenOptionsWrapper), so there is no port race at all.
func startNaiveTestServer(t *testing.T, username, password, serverName, certPEM, keyPEM string) uint16 {
	t.Helper()

	cfg := fmt.Sprintf(`{
  "inbounds": [
    {
      "type": "naive",
      "tag": "naive-in",
      "listen": "127.0.0.1",
      "listen_port": 0,
      "network": "tcp",
      "users": [{"username": %q, "password": %q}],
      "tls": {
        "enabled": true,
        "server_name": %q,
        "certificate": [%q],
        "key": [%q]
      }
    }
  ],
  "outbounds": [{"type": "direct", "tag": "direct"}]
}`, username, password, serverName, certPEM, keyPEM)

	ctx := include.Context(context.Background())
	var opts option.Options
	if err := opts.UnmarshalJSONContext(ctx, []byte(cfg)); err != nil {
		t.Fatalf("parse naive server config: %v", err)
	}
	inst, err := RunInstanceRaw(ctx, &opts)
	if err != nil {
		t.Fatalf("start naive server side-instance: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
	if inst.ListenPort == 0 {
		t.Fatal("naive server side-instance reported no listen port")
	}
	return inst.ListenPort
}

// TestUrlTestConfig_Naive_Live is the liveness gate for the naive outbound —
// our strongest anti-DPI fallback. It proves, hermetically (loopback only):
//
//	config JSON → option.NaiveOutboundOptions parse → registry → cronet engine
//	actually starts (the runtime library loads/links and initializes) → real
//	TLS+h2 handshake against a genuine naive server → padded CONNECT stream →
//	HTTP 204 measured THROUGH the tunnel.
//
// What it deliberately does NOT cover: the Windows purego runtime-DLL path and
// the libcronet.dll↔go.mod version sync (that lives in
// scripts/sync-naive-lib-windows.ps1 + the build pipeline) — this test links
// cronet statically, so a Windows DLL desync stays invisible here.
func TestUrlTestConfig_Naive_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up a cronet engine and a naive server")
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	targetAddr := target.Listener.Addr().String()

	const username, password = "inhive_test", "inhive_test_password"
	const serverName = "example.org"
	caPEM, certPEM, keyPEM := naiveTestCertificates(t, serverName)
	port := startNaiveTestServer(t, username, password, serverName, certPEM, keyPEM)

	cfg := fmt.Sprintf(`{
  "outbounds": [
    {
      "type": "naive",
      "tag": "naive-live",
      "server": "127.0.0.1",
      "server_port": %d,
      "username": %q,
      "password": %q,
      "tls": {
        "enabled": true,
        "server_name": %q,
        "certificate": [%q]
      }
    },
    {"type": "direct", "tag": "direct"}
  ]
}`, port, username, password, serverName, caPEM)

	resp, err := (&CoreService{}).UrlTestConfig(context.Background(), &UrlTestConfigRequest{
		ConfigJson: cfg,
		Url:        "http://" + targetAddr + "/generate_204",
		TimeoutMs:  20000,
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("ping through a live naive tunnel must succeed, got: bring_up=%v rejected=%v err=%s",
			resp.BringUpFailed, resp.ConfigRejected, resp.Error)
	}
	if resp.DelayMs <= 0 {
		t.Fatalf("expected positive delay, got %d", resp.DelayMs)
	}
	t.Logf("live naive tunnel ping: %d ms", resp.DelayMs)
}
