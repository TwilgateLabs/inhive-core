package hcore

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Tests for probe_helpers.go. Moved from warm_probe_test.go on 2026-09-23 together
// with the helpers; the warm-pool tests were deleted with the pool.

// ── fakeDialer ───────────────────────────────────────────────────────────────
//
// A fakeDialer forwards every DialContext to a fixed TCP address (an httptest
// server), so probeThroughDetour drives a REAL HTTP HEAD + status check without
// leaving the machine — the probe HTTP path runs under `-short`.

type fakeDialer struct {
	target  string // host:port of the local httptest server
	dialErr error  // if set, DialContext fails (simulates a dead outbound)
	dials   int
}

func (d *fakeDialer) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
	d.dials++
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "tcp", d.target)
}

func (d *fakeDialer) ListenPacket(ctx context.Context, dest M.Socksaddr) (net.PacketConn, error) {
	return nil, net.ErrClosed
}

var _ N.Dialer = (*fakeDialer)(nil)

// ── probeThroughDetour: status enforcement (hijack guard) ────────────────────

func TestProbeThroughDetour_StatusEnforcement(t *testing.T) {
	cases := []struct {
		name           string
		serverStatus   int
		expectedStatus int
		wantOK         bool
	}{
		{"204 accepted by default", http.StatusNoContent, 0, true},
		{"200 accepted by default", http.StatusOK, 0, true},
		{"hijack 302 rejected by default", http.StatusFound, 0, false},
		{"hijack 403 rejected by default", http.StatusForbidden, 0, false},
		{"explicit 204 required, 200 rejected", http.StatusOK, http.StatusNoContent, false},
		{"explicit 200 required, 200 accepted", http.StatusOK, http.StatusOK, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.serverStatus)
			}))
			defer srv.Close()
			host := srv.Listener.Addr().String()
			d := &fakeDialer{target: host}

			delay, err := probeThroughDetour(context.Background(), "http://"+host+"/generate_204", d, tc.expectedStatus)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected success, got error: %v", err)
				}
				if delay == 0 {
					t.Fatalf("success must report non-zero delay")
				}
			} else {
				if err == nil {
					t.Fatalf("expected status rejection, got delay=%d", delay)
				}
			}
		})
	}
}

func TestProbeThroughDetour_DeadDialer(t *testing.T) {
	d := &fakeDialer{dialErr: net.ErrClosed}
	delay, err := probeThroughDetour(context.Background(), "https://example.invalid/generate_204", d, 0)
	if err == nil {
		t.Fatalf("dead dialer must error, got delay=%d", delay)
	}
	if delay != 0 {
		t.Fatalf("dead dialer must report 0 delay, got %d", delay)
	}
}

func TestProbeThroughDetour_NilDialer(t *testing.T) {
	if _, err := probeThroughDetour(context.Background(), "", nil, 0); err == nil {
		t.Fatalf("nil dialer must error")
	}
}

// ── statusOK / probeHostPort ─────────────────────────────────────────────────

func TestStatusOK(t *testing.T) {
	cases := []struct {
		code, expected int
		want           bool
	}{
		{204, 0, true},
		{200, 0, true},
		{302, 0, false},
		{403, 0, false},
		{204, 204, true},
		{200, 204, false},
		{200, 200, true},
	}
	for _, tc := range cases {
		if got := statusOK(tc.code, tc.expected); got != tc.want {
			t.Fatalf("statusOK(%d,%d)=%v want %v", tc.code, tc.expected, got, tc.want)
		}
	}
}

func TestProbeHostPort(t *testing.T) {
	cases := []struct {
		link string
		want string
	}{
		{"https://www.gstatic.com/generate_204", "www.gstatic.com:443"},
		{"http://cp.cloudflare.com", "cp.cloudflare.com:80"},
		{"https://example.com:8443/x", "example.com:8443"},
	}
	for _, tc := range cases {
		got, err := probeHostPort(tc.link)
		if err != nil {
			t.Fatalf("probeHostPort(%q): %v", tc.link, err)
		}
		if got.String() != tc.want {
			t.Fatalf("probeHostPort(%q)=%q want %q", tc.link, got.String(), tc.want)
		}
	}
}
