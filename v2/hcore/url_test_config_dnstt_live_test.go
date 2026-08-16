package hcore

// Hermetic liveness gate for the dnstt outbound (protocol/dnstt). The responder
// half below is a faithful port of the reference dnstt-server
// (www.bamsoftware.com/git/dnstt.git dnstt-server/main.go) onto the SAME
// importable library packages our client uses (dns, noise, turbotunnel, kcp,
// smux) — logging stripped, upstream pinned to the local test target. Wire
// behavior (base32 query names, TXT answers, EDNS(0) size enforcement, KCP
// parameters, Noise NK, smux v2) is kept intact so the test exercises the real
// protocol, not a lookalike.

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
	"www.bamsoftware.com/git/dnstt.git/dns"
	"www.bamsoftware.com/git/dnstt.git/noise"
	"www.bamsoftware.com/git/dnstt.git/turbotunnel"
)

const (
	dnsttTestIdleTimeout      = 2 * time.Minute
	dnsttTestResponseTTL      = 60
	dnsttTestMaxResponseDelay = 1 * time.Second
	// 1280 (min IPv6 MTU) - 40 (IPv6 header) - 8 (UDP header), as in dnstt-server.
	dnsttTestMaxUDPPayload = 1280 - 40 - 8
)

var dnsttTestBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// dnsttTestNextPacket reads the next length-prefixed packet from a query
// payload, skipping padding (prefix >= 224), exactly as dnstt-server does.
func dnsttTestNextPacket(r *bytes.Reader) ([]byte, error) {
	eof := func(err error) error {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return err
	}
	for {
		prefix, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if prefix >= 224 {
			paddingLen := prefix - 224
			_, err := io.CopyN(io.Discard, r, int64(paddingLen))
			if err != nil {
				return nil, eof(err)
			}
		} else {
			p := make([]byte, int(prefix))
			_, err = io.ReadFull(r, p)
			return p, eof(err)
		}
	}
}

// dnsttTestResponseFor constructs the response for a query, returning the
// decoded upstream payload — dnstt-server's responseFor with logging removed.
func dnsttTestResponseFor(query *dns.Message, domain dns.Name) (*dns.Message, []byte) {
	resp := &dns.Message{
		ID:       query.ID,
		Flags:    0x8000, // QR = 1, RCODE = no error
		Question: query.Question,
	}
	if query.Flags&0x8000 != 0 {
		return nil, nil // not a query
	}
	payloadSize := 0
	for _, rr := range query.Additional {
		if rr.Type != dns.RRTypeOPT {
			continue
		}
		if len(resp.Additional) != 0 {
			resp.Flags |= dns.RcodeFormatError
			return resp, nil
		}
		resp.Additional = append(resp.Additional, dns.RR{
			Name:  dns.Name{},
			Type:  dns.RRTypeOPT,
			Class: 4096,
			TTL:   0,
			Data:  []byte{},
		})
		additional := &resp.Additional[0]
		version := (rr.TTL >> 16) & 0xff
		if version != 0 {
			resp.Flags |= dns.ExtendedRcodeBadVers & 0xf
			additional.TTL = (dns.ExtendedRcodeBadVers >> 4) << 24
			return resp, nil
		}
		payloadSize = int(rr.Class)
	}
	if payloadSize < 512 {
		payloadSize = 512
	}
	if len(query.Question) != 1 {
		resp.Flags |= dns.RcodeFormatError
		return resp, nil
	}
	question := query.Question[0]
	prefix, ok := question.Name.TrimSuffix(domain)
	if !ok {
		resp.Flags |= dns.RcodeNameError
		return resp, nil
	}
	resp.Flags |= 0x0400 // AA = 1
	if query.Opcode() != 0 {
		resp.Flags |= dns.RcodeNotImplemented
		return resp, nil
	}
	if question.Type != dns.RRTypeTXT {
		resp.Flags |= dns.RcodeNameError
		return resp, nil
	}
	encoded := bytes.ToUpper(bytes.Join(prefix, nil))
	payload := make([]byte, dnsttTestBase32.DecodedLen(len(encoded)))
	n, err := dnsttTestBase32.Decode(payload, encoded)
	if err != nil {
		resp.Flags |= dns.RcodeNameError
		return resp, nil
	}
	payload = payload[:n]
	if payloadSize < dnsttTestMaxUDPPayload {
		resp.Flags |= dns.RcodeFormatError
		return resp, nil
	}
	return resp, payload
}

type dnsttTestRecord struct {
	Resp     *dns.Message
	Addr     net.Addr
	ClientID turbotunnel.ClientID
}

func dnsttTestRecvLoop(domain dns.Name, dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch chan<- *dnsttTestRecord) error {
	for {
		var buf [4096]byte
		n, addr, err := dnsConn.ReadFrom(buf[:])
		if err != nil {
			return err
		}
		query, err := dns.MessageFromWireFormat(buf[:n])
		if err != nil {
			continue
		}
		resp, payload := dnsttTestResponseFor(&query, domain)
		var clientID turbotunnel.ClientID
		n = copy(clientID[:], payload)
		payload = payload[n:]
		if n == len(clientID) {
			r := bytes.NewReader(payload)
			for {
				p, err := dnsttTestNextPacket(r)
				if err != nil {
					break
				}
				ttConn.QueueIncoming(p, clientID)
			}
		} else if resp != nil && resp.Rcode() == dns.RcodeNoError {
			resp.Flags |= dns.RcodeNameError
		}
		if resp != nil {
			select {
			case ch <- &dnsttTestRecord{resp, addr, clientID}:
			default:
			}
		}
	}
}

func dnsttTestSendLoop(dnsConn net.PacketConn, ttConn *turbotunnel.QueuePacketConn, ch <-chan *dnsttTestRecord, maxEncodedPayload int) error {
	var nextRec *dnsttTestRecord
	for {
		rec := nextRec
		nextRec = nil
		if rec == nil {
			var ok bool
			rec, ok = <-ch
			if !ok {
				break
			}
		}
		if rec.Resp.Rcode() == dns.RcodeNoError && len(rec.Resp.Question) == 1 {
			rec.Resp.Answer = []dns.RR{
				{
					Name:  rec.Resp.Question[0].Name,
					Type:  rec.Resp.Question[0].Type,
					Class: rec.Resp.Question[0].Class,
					TTL:   dnsttTestResponseTTL,
					Data:  nil,
				},
			}
			var payload bytes.Buffer
			limit := maxEncodedPayload
			timer := time.NewTimer(dnsttTestMaxResponseDelay)
			timerExpired := false
			for {
				var p []byte
				unstash := ttConn.Unstash(rec.ClientID)
				outgoing := ttConn.OutgoingQueue(rec.ClientID)
				select {
				case p = <-unstash:
				default:
					select {
					case p = <-unstash:
					case p = <-outgoing:
					default:
						select {
						case p = <-unstash:
						case p = <-outgoing:
						case <-timer.C:
							timerExpired = true
						case nextRec = <-ch:
						}
					}
				}
				if !timerExpired && !timer.Stop() {
					<-timer.C
				}
				timer.Reset(0)
				timerExpired = false
				if len(p) == 0 {
					break
				}
				limit -= 2 + len(p)
				if payload.Len() == 0 {
					// First packet unconditionally.
				} else if limit < 0 {
					ttConn.Stash(p, rec.ClientID)
					break
				}
				binary.Write(&payload, binary.BigEndian, uint16(len(p)))
				payload.Write(p)
			}
			if !timerExpired && !timer.Stop() {
				<-timer.C
			}
			rec.Resp.Answer[0].Data = dns.EncodeRDataTXT(payload.Bytes())
		}
		buf, err := rec.Resp.WireFormat()
		if err != nil {
			continue
		}
		if len(buf) > dnsttTestMaxUDPPayload {
			buf = buf[:dnsttTestMaxUDPPayload]
			buf[2] |= 0x02 // TC = 1
		}
		_, err = dnsConn.WriteTo(buf, rec.Addr)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			continue
		}
	}
	return nil
}

// dnsttTestComputeMaxEncodedPayload is dnstt-server's computeMaxEncodedPayload:
// max TXT RDATA that keeps a worst-case response under the UDP payload limit.
func dnsttTestComputeMaxEncodedPayload(t *testing.T, limit int) int {
	t.Helper()
	maxLengthName, err := dns.NewName([][]byte{
		bytes.Repeat([]byte("A"), 63),
		bytes.Repeat([]byte("A"), 63),
		bytes.Repeat([]byte("A"), 63),
		bytes.Repeat([]byte("A"), 61),
	})
	if err != nil {
		t.Fatalf("max-length name: %v", err)
	}
	queryLimit := uint16(limit)
	if int(queryLimit) != limit {
		queryLimit = 0xffff
	}
	query := &dns.Message{
		Question: []dns.Question{
			{Name: maxLengthName, Type: dns.RRTypeTXT, Class: dns.RRTypeTXT},
		},
		Additional: []dns.RR{
			{Name: dns.Name{}, Type: dns.RRTypeOPT, Class: queryLimit, TTL: 0, Data: []byte{}},
		},
	}
	resp, _ := dnsttTestResponseFor(query, dns.Name([][]byte{}))
	resp.Answer = []dns.RR{
		{
			Name:  query.Question[0].Name,
			Type:  query.Question[0].Type,
			Class: query.Question[0].Class,
			TTL:   dnsttTestResponseTTL,
			Data:  nil,
		},
	}
	low := 0
	high := 32768
	for low+1 < high {
		mid := (low + high) / 2
		resp.Answer[0].Data = dns.EncodeRDataTXT(make([]byte, mid))
		buf, err := resp.WireFormat()
		if err != nil {
			t.Fatalf("WireFormat: %v", err)
		}
		if len(buf) <= limit {
			low = mid
		} else {
			high = mid
		}
	}
	return low
}

// dnsttTestHandleStream pipes an accepted smux stream to the (only) allowed
// upstream — the local test HTTP server.
func dnsttTestHandleStream(stream *smux.Stream, upstream string) {
	upstreamConn, err := net.DialTimeout("tcp", upstream, 10*time.Second)
	if err != nil {
		stream.Close()
		return
	}
	defer upstreamConn.Close()
	upstreamTCP := upstreamConn.(*net.TCPConn)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, upstreamTCP)
		upstreamTCP.CloseRead()
		stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstreamTCP, stream)
		upstreamTCP.CloseWrite()
	}()
	wg.Wait()
}

func dnsttTestAcceptStreams(conn *kcp.UDPSession, privkey []byte, upstream string) error {
	rw, err := noise.NewServer(conn, privkey)
	if err != nil {
		return err
	}
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = 2
	smuxConfig.KeepAliveTimeout = dnsttTestIdleTimeout
	smuxConfig.MaxStreamBuffer = 1 * 1024 * 1024
	sess, err := smux.Server(rw, smuxConfig)
	if err != nil {
		return err
	}
	defer sess.Close()
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			return err
		}
		go func() {
			defer stream.Close()
			dnsttTestHandleStream(stream, upstream)
		}()
	}
}

func dnsttTestAcceptSessions(ln *kcp.Listener, privkey []byte, mtu int, upstream string) error {
	for {
		conn, err := ln.AcceptKCP()
		if err != nil {
			return err
		}
		conn.SetStreamMode(true)
		conn.SetNoDelay(0, 0, 0, 1)
		conn.SetWindowSize(turbotunnel.QueueSize/2, turbotunnel.QueueSize/2)
		if rc := conn.SetMtu(mtu); !rc {
			conn.Close()
			continue
		}
		go func() {
			defer conn.Close()
			_ = dnsttTestAcceptStreams(conn, privkey, upstream)
		}()
	}
}

// startDnsttTestResponder starts a genuine dnstt server on a loopback UDP
// socket. All tunnelled streams are piped to `upstream` (the local 204 server).
// Returns the DNS resolver address for the client and the server public key.
func startDnsttTestResponder(t *testing.T, domain dns.Name, upstream string) (resolverAddr string, pubkeyHex string) {
	t.Helper()

	privkey, err := noise.GeneratePrivkey()
	if err != nil {
		t.Fatalf("GeneratePrivkey: %v", err)
	}
	pubkeyHex = fmt.Sprintf("%x", noise.PubkeyFromPrivkey(privkey))

	dnsConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { dnsConn.Close() })
	resolverAddr = dnsConn.LocalAddr().String()

	maxEncodedPayload := dnsttTestComputeMaxEncodedPayload(t, dnsttTestMaxUDPPayload)
	mtu := maxEncodedPayload - 2 // 2 bytes for the packet length prefix
	if mtu < 80 {
		t.Fatalf("effective MTU %d too small", mtu)
	}

	ttConn := turbotunnel.NewQueuePacketConn(turbotunnel.DummyAddr{}, dnsttTestIdleTimeout*2)
	ln, err := kcp.ServeConn(nil, 0, 0, ttConn)
	if err != nil {
		t.Fatalf("kcp.ServeConn: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	ch := make(chan *dnsttTestRecord, 100)
	go func() { _ = dnsttTestAcceptSessions(ln, privkey, mtu, upstream) }()
	go func() { _ = dnsttTestSendLoop(dnsConn, ttConn, ch, maxEncodedPayload) }()
	go func() {
		defer close(ch)
		_ = dnsttTestRecvLoop(domain, dnsConn, ttConn, ch)
	}()

	return resolverAddr, pubkeyHex
}

// TestUrlTestConfig_Dnstt_Live is the liveness gate for the dnstt outbound.
// Hermetic (loopback only): a genuine dnstt server (ported from the reference
// dnstt-server onto the same library packages) answers on a local UDP socket,
// and the probe must fetch a real HTTP 204 THROUGH the full client chain:
//
//	config JSON → option.DnsttOutboundOptions parse → registry → DNSPacketConn
//	base32/TXT encoding → KCP → Noise NK handshake → smux stream → 204.
//
// Any refactoring that breaks the DNS encoding, the KCP/smux parameters or the
// Noise handshake turns this red in CI instead of surfacing as user reports.
func TestUrlTestConfig_Dnstt_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("brings up a userspace dnstt server")
	}

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	targetAddr := target.Listener.Addr().String()

	tunnelDomain, err := dns.ParseName("t.example.com")
	if err != nil {
		t.Fatalf("ParseName: %v", err)
	}
	resolverAddr, pubkeyHex := startDnsttTestResponder(t, tunnelDomain, targetAddr)

	cfg := fmt.Sprintf(`{
  "outbounds": [
    {
      "type": "dnstt",
      "tag": "dnstt-live",
      "domain": "t.example.com",
      "pubkey": %q,
      "resolver": %q
    },
    {"type": "direct", "tag": "direct"}
  ]
}`, pubkeyHex, resolverAddr)

	resp, err := (&CoreService{}).UrlTestConfig(context.Background(), &UrlTestConfigRequest{
		ConfigJson: cfg,
		Url:        "http://" + targetAddr + "/generate_204",
		TimeoutMs:  20000,
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("ping through a live dnstt tunnel must succeed, got: bring_up=%v rejected=%v err=%s",
			resp.BringUpFailed, resp.ConfigRejected, resp.Error)
	}
	if resp.DelayMs <= 0 {
		t.Fatalf("expected positive delay, got %d", resp.DelayMs)
	}
	t.Logf("live dnstt tunnel ping: %d ms", resp.DelayMs)
}
