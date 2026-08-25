package ray2sing

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

// normalizeWgKey validates a WireGuard/AWG curve25519 key and returns it
// re-encoded in the standard base64 alphabet (what sing-box's endpoint
// creation decodes with base64.StdEncoding). Accepts the url-safe alphabet
// and missing padding (subscription tooling re-encodes/strips both). An
// empty value is returned as-is — optionality is the caller's decision.
//
// A key that is not base64 fails sing-box at endpoint CREATION; a key that
// decodes to != 32 bytes passes creation and kills the WHOLE profile inside
// IpcSet at Start (FromHex's length check in wireguard-go noise-types.go) —
// so both are rejected HERE with an error naming the parameter. Key material
// is deliberately never echoed into the error text (it lands in logs).
func normalizeWgKey(name, val string) (string, error) {
	k := strings.TrimSpace(val)
	if k == "" {
		return "", nil
	}
	k = strings.ReplaceAll(k, "-", "+")
	k = strings.ReplaceAll(k, "_", "/")
	k = strings.TrimRight(k, "=")
	if n := len(k) % 4; n != 0 {
		k += strings.Repeat("=", 4-n)
	}
	raw, err := base64.StdEncoding.DecodeString(k)
	if err != nil {
		return "", fmt.Errorf("invalid %s: not valid base64 (%d chars)", name, len(val))
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("invalid %s: decodes to %d bytes, want 32", name, len(raw))
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// validateMagicHeader checks an H1-H4 spec against the exact grammar the
// linked amneziawg-go v0.2.19 accepts (device/magic-header.go newMagicHeader):
// a decimal uint32, or a "start-end" decimal range with end >= start. Hex
// ("0x..."), overflow and reversed ranges fail newMagicHeader inside IpcSet
// at Start and kill the whole profile — reject them here instead, naming the
// parameter and value.
func validateMagicHeader(name, spec string) error {
	if spec == "" {
		return nil
	}
	parts := strings.Split(spec, "-")
	if len(parts) > 2 {
		return fmt.Errorf("invalid %s %q: want a decimal uint32 or \"start-end\" range", name, spec)
	}
	start, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return fmt.Errorf("invalid %s %q: want a decimal uint32 or \"start-end\" range", name, spec)
	}
	if len(parts) == 2 {
		end, err := strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return fmt.Errorf("invalid %s %q: want a decimal uint32 or \"start-end\" range", name, spec)
		}
		if end < start {
			return fmt.Errorf("invalid %s %q: range is reversed", name, spec)
		}
	}
	return nil
}

// validateObfSpec checks an I1-I5 obfuscation spec against the tag vocabulary
// of the LINKED amneziawg-go v0.2.19 (device/obf.go obfBuilders): b, t, r,
// rc, rd, d, ds, dz. The official AWG 1.5 tags <c> (counter) and <wt> (wait
// timeout) are NOT in that runtime — newObfChain returns "unknown tag" from
// IpcSet at Start, killing the whole profile, so an unsupported/malformed
// spec is rejected here with an error naming the parameter. Value grammar
// mirrors the builders: <b>/<d> take hex bytes (b requires them, even
// length), <r>/<rc>/<rd>/<dz> take a non-negative decimal length (a negative
// length passes Atoi in the builder but panics on slicing at packet time),
// <t>/<ds> ignore their value.
func validateObfSpec(name, spec string) error {
	if spec == "" {
		return nil
	}
	remaining := spec
	for {
		start := strings.IndexByte(remaining, '<')
		if start == -1 {
			break
		}
		end := strings.IndexByte(remaining[start:], '>')
		if end == -1 {
			return fmt.Errorf("invalid %s %q: missing enclosing '>'", name, spec)
		}
		end += start
		parts := strings.Fields(remaining[start+1 : end])
		if len(parts) == 0 {
			return fmt.Errorf("invalid %s %q: empty tag", name, spec)
		}
		key := parts[0]
		val := ""
		if len(parts) > 1 {
			val = parts[1]
		}
		switch key {
		case "b":
			v := strings.TrimPrefix(val, "0x")
			if v == "" || len(v)%2 != 0 {
				return fmt.Errorf("invalid %s %q: tag <b> needs an even-length hex value", name, spec)
			}
			if _, err := hex.DecodeString(v); err != nil {
				return fmt.Errorf("invalid %s %q: tag <b> value is not hex", name, spec)
			}
		case "t", "d", "ds":
			// value ignored by the builder
		case "r", "rc", "rd", "dz":
			n, err := strconv.Atoi(val)
			if err != nil || n < 0 {
				return fmt.Errorf("invalid %s %q: tag <%s> needs a non-negative decimal length", name, spec, key)
			}
		default:
			return fmt.Errorf("invalid %s %q: tag <%s> is not supported by the linked amneziawg runtime (supported: b, t, r, rc, rd, d, ds, dz)", name, spec, key)
		}
		remaining = remaining[end+1:]
	}
	return nil
}

// clampAwgInt drops (returns 0 = omitted from the UAPI config) a parsed AWG
// numeric param that is below its accepted minimum, logging the correction.
// amneziawg-go v0.2.19 rejects jc/jmin/jmax <= 0 ("must be a positive
// value") and s1-s4 < 0 ("must be non-negative") inside IpcSet at Start —
// a whole-profile kill for one bad link. 0 always means "not set".
func clampAwgInt(name string, v, min int) int {
	if v != 0 && v < min {
		skip("awg", fmt.Sprintf("dropping %s=%d: below minimum %d", name, v, min))
		return 0
	}
	return v
}

// parseReservedList parses a comma-separated Cloudflare/WARP reserved list.
// The plain-WireGuard endpoint rejects any count other than exactly 3 at
// endpoint creation (transport/wireguard/endpoint.go), and the awg endpoint
// silently ignores a wrong count — both wrong outcomes, so a non-empty list
// must have exactly 3 byte values or the link fails with a clear error.
func parseReservedList(raw string) ([]uint8, error) {
	var out []uint8
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		num, err := strconv.ParseUint(part, 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid reserved %q: values must be bytes (0-255)", raw)
		}
		out = append(out, uint8(num))
	}
	if len(out) != 0 && len(out) != 3 {
		return nil, fmt.Errorf("invalid reserved %q: want exactly 3 comma-separated values, got %d", raw, len(out))
	}
	return out, nil
}

func AWGSingboxTxt(content string) (*T.Endpoint, error) {

	var (
		privateKey                         string
		addresses                          []netip.Prefix
		mtu                                uint32
		jc, jmin, jmax                     int
		s1, s2, s3, s4                     int
		h1, h2, h3, h4, i1, i2, i3, i4, i5 string
		j1, j2, j3                         string
		itime                              int

		peers    []T.AwgPeerOptions
		peer     T.AwgPeerOptions
		havePeer bool
	)

	// flushPeer commits the peer currently being parsed into the peers slice.
	flushPeer := func() {
		if havePeer {
			peers = append(peers, peer)
			peer = T.AwgPeerOptions{}
			havePeer = false
		}
	}

	section := ""

	lines := strings.Split(content, "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			// A new section closes the peer currently being accumulated so each
			// [Peer] block becomes its own entry instead of overwriting the last.
			flushPeer()
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		// key = value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])

		switch section {
		case "interface":
			switch key {
			case "PrivateKey":
				privateKey = val

			case "Address":
				for _, add := range strings.Split(val, ",") {
					pfx, err := netip.ParsePrefix(strings.TrimSpace(add))
					if err != nil {
						return nil, fmt.Errorf("invalid Address: %w", err)
					}
					addresses = append(addresses, pfx)
				}
			case "MTU":
				if v, err := strconv.ParseUint(val, 10, 32); err == nil {
					mtu = uint32(v)
				}
			case "Jc":
				jc, _ = strconv.Atoi(val)
			case "Jmin":
				jmin, _ = strconv.Atoi(val)
			case "Jmax":
				jmax, _ = strconv.Atoi(val)

			case "S1":
				s1, _ = strconv.Atoi(val)
			case "S2":
				s2, _ = strconv.Atoi(val)
			case "S3":
				s3, _ = strconv.Atoi(val)
			case "S4":
				s4, _ = strconv.Atoi(val)
			case "H1":
				h1 = val
			case "H2":
				h2 = val
			case "H3":
				h3 = val
			case "H4":
				h4 = val
			case "I1":
				i1 = val
			case "I2":
				i2 = val
			case "I3":
				i3 = val
			case "I4":
				i4 = val
			case "I5":
				i5 = val
			// AmneziaWG 1.5 controlled-junk generators + inter-handshake timeout.
			case "J1":
				j1 = val
			case "J2":
				j2 = val
			case "J3":
				j3 = val
			case "Itime", "ITime", "ITIME":
				itime, _ = strconv.Atoi(val)
			}

		case "peer":
			havePeer = true
			switch key {
			case "PublicKey":
				peer.PublicKey = val
			case "PresharedKey":
				peer.PresharedKey = val
			// Cloudflare/WARP 3-byte reserved (comma-separated). Applied in the bind
			// at send time since WireGuard's UAPI has no reserved key.
			case "Reserved":
				for _, part := range strings.Split(val, ",") {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					num, err := strconv.ParseUint(part, 10, 8)
					if err != nil {
						return nil, fmt.Errorf("invalid Reserved: %w", err)
					}
					peer.Reserved = append(peer.Reserved, uint8(num))
				}

			case "AllowedIPs":
				// wg-quick allows a comma-separated list ("0.0.0.0/0, ::/0" —
				// exactly what Amnezia's generator writes) and repeating the key;
				// both semantics are append. A single ParsePrefix(val) here used
				// to hard-fail the WHOLE conf on the typical Amnezia file.
				for _, part := range strings.Split(val, ",") {
					part = strings.TrimSpace(part)
					if part == "" {
						continue
					}
					pfx, err := netip.ParsePrefix(part)
					if err != nil {
						return nil, fmt.Errorf("invalid AllowedIPs: %w", err)
					}
					peer.AllowedIPs = append(peer.AllowedIPs, pfx)
				}

			case "Endpoint":
				host, portStr, err := net.SplitHostPort(val)
				if err != nil {
					return nil, fmt.Errorf("invalid Endpoint: %w", err)
				}
				port, err := strconv.Atoi(portStr)
				if err != nil {
					return nil, fmt.Errorf("invalid Endpoint port: %w", err)
				}
				peer.Address = host
				peer.Port = uint16(port)

			case "PersistentKeepalive":
				v, _ := strconv.Atoi(val)
				peer.PersistentKeepaliveInterval = uint16(v)
			}
		}
	}

	// Commit the final [Peer] block that was still being accumulated.
	flushPeer()

	if privateKey == "" {
		return nil, errors.New("missing PrivateKey")
	}
	privateKey, err := normalizeWgKey("PrivateKey", privateKey)
	if err != nil {
		return nil, err
	}

	if len(peers) == 0 {
		return nil, errors.New("missing peer Endpoint")
	}
	for i := range peers {
		if peers[i].Address == "" || peers[i].Port == 0 {
			return nil, errors.New("missing peer Endpoint")
		}
		// The URL path rejects a missing peer public key (see AWGSingbox); an
		// INI [Peer] without one used to slip through and fail IpcSet at Start.
		if peers[i].PublicKey == "" {
			return nil, errors.New("missing peer PublicKey")
		}
		if peers[i].PublicKey, err = normalizeWgKey("PublicKey", peers[i].PublicKey); err != nil {
			return nil, err
		}
		if peers[i].PresharedKey, err = normalizeWgKey("PresharedKey", peers[i].PresharedKey); err != nil {
			return nil, err
		}
		if n := len(peers[i].Reserved); n != 0 && n != 3 {
			return nil, fmt.Errorf("invalid Reserved: want exactly 3 comma-separated values, got %d", n)
		}
		if len(peers[i].AllowedIPs) == 0 {
			peers[i].AllowedIPs = badoption.Listable[netip.Prefix]([]netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
			})
		}
	}

	// Out-of-range AWG numerics are dropped (0 = omitted); junk H/I specs fail
	// the conf — both would otherwise kill the whole profile inside IpcSet at
	// Start (see the helper docs).
	jc, jmin, jmax = clampAwgInt("Jc", jc, 1), clampAwgInt("Jmin", jmin, 1), clampAwgInt("Jmax", jmax, 1)
	s1, s2, s3, s4 = clampAwgInt("S1", s1, 0), clampAwgInt("S2", s2, 0), clampAwgInt("S3", s3, 0), clampAwgInt("S4", s4, 0)
	itime = clampAwgInt("Itime", itime, 0)
	for _, h := range []struct{ name, spec string }{{"H1", h1}, {"H2", h2}, {"H3", h3}, {"H4", h4}} {
		if err := validateMagicHeader(h.name, h.spec); err != nil {
			return nil, err
		}
	}
	for _, i := range []struct{ name, spec string }{{"I1", i1}, {"I2", i2}, {"I3", i3}, {"I4", i4}, {"I5", i5}} {
		if err := validateObfSpec(i.name, i.spec); err != nil {
			return nil, err
		}
	}

	// isAwg is true when AmneziaWG obfs params (Jc/S/H/I/J/Itime) are present; a
	// plain WireGuard .conf carries none of them and must be emitted as
	// TypeWireGuard.
	isAwg := !(jc+jmin+jmax+s1+s2+s3+s4+itime == 0 && h1+h2+h3+h4+i1+i2+i3+i4+i5+j1+j2+j3 == "")

	if !isAwg {
		wgPeers := make([]T.WireGuardPeer, 0, len(peers))
		for _, p := range peers {
			wgPeers = append(wgPeers, T.WireGuardPeer{
				Address:                     p.Address,
				Port:                        p.Port,
				PreSharedKey:                p.PresharedKey,
				PublicKey:                   p.PublicKey,
				AllowedIPs:                  p.AllowedIPs,
				PersistentKeepaliveInterval: p.PersistentKeepaliveInterval,
				Reserved:                    p.Reserved,
			})
		}
		wgopts := &T.WireGuardEndpointOptions{
			PrivateKey: privateKey,
			Address:    badoption.Listable[netip.Prefix](addresses),
			Peers:      wgPeers,
		}
		if mtu != 0 {
			wgopts.MTU = mtu
		}
		return &T.Endpoint{
			Type: C.TypeWireGuard,
			// The tag doubles as the user-visible server name in the app
			// (URI #fragment / JSON tag) — was the "wiregaurd" typo.
			Tag:     "wireguard",
			Options: wgopts,
		}, nil
	}

	out := &T.Endpoint{
		Type: C.TypeAwg,
		Tag:  "awg", // adjust if you derive tag elsewhere
		Options: &T.AwgEndpointOptions{

			PrivateKey: privateKey,
			Address:    badoption.Listable[netip.Prefix](addresses),
			MTU:        mtu,

			Jc:   jc,
			Jmin: jmin,
			Jmax: jmax,

			S1: s1,
			S2: s2,
			S3: s3,
			S4: s4,
			H1: h1,
			H2: h2,
			H3: h3,
			H4: h4,

			I1: i1,
			I2: i2,
			I3: i3,
			I4: i4,
			I5: i5,

			J1:    j1,
			J2:    j2,
			J3:    j3,
			Itime: itime,

			Peers: peers,
		},
	}

	return out, nil
}

func AWGSingbox(raw string) (*T.Endpoint, error) {
	splt := strings.SplitN(raw, "://", 2)
	if len(splt) == 2 {
		d, _ := decodeBase64IfNeeded(splt[1])
		raw = splt[0] + "://" + d
	}
	u, err := ParseUrl(raw, 0)

	if err != nil || len(u.Params) == 0 {
		if end, err2 := AWGSingboxTxt(raw); err2 == nil {
			return end, nil
		}
		return nil, err
	}

	getInt := func(key string) int {
		if v, ok := u.Params[key]; ok {
			i, _ := strconv.Atoi(v)
			return i
		}
		return 0
	}

	getUint16OfN := func(keys ...string) uint16 {
		for _, key := range keys {
			if v, ok := u.Params[key]; ok {
				i, _ := strconv.Atoi(v)
				return uint16(i)
			}
		}
		return 0
	}

	parsePrefixes := func(raw string) (badoption.Listable[netip.Prefix], error) {
		var out []netip.Prefix
		for _, s := range strings.Split(raw, ",") {
			if s != "" {
				p, err := netip.ParsePrefix(strings.TrimSpace(s))
				if err != nil {
					p2, err2 := netip.ParsePrefix(strings.TrimSpace(s) + "/24")
					if err2 != nil {
						return nil, fmt.Errorf("invalid %s: %w", raw, err)
					}
					p = p2
				}
				out = append(out, p)
			}
		}
		return badoption.Listable[netip.Prefix](out), nil
	}

	addresses, err := parsePrefixes(getOneOfN(u.Params, "", "ip", "address"))
	if err != nil {
		return nil, err
	}

	allowedIPs, err := parsePrefixes(getOneOfN(u.Params, "", "localaddress", "allowedips"))
	if err != nil {
		return nil, err
	}
	if len(allowedIPs) == 0 {
		allowedIPs = badoption.Listable[netip.Prefix]([]netip.Prefix{
			netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
		})
	}

	peer := T.AwgPeerOptions{
		Address:                     u.Hostname,
		Port:                        u.Port,
		PublicKey:                   getOneOfN(u.Params, "", "peerpublickey", "publickey", "pub", "peerpub"),
		PresharedKey:                getOneOfN(u.Params, "", "presharedkey", "psk"),
		AllowedIPs:                  allowedIPs,
		PersistentKeepaliveInterval: getUint16OfN("keepalive", "persistentkeepalive", "pk_keepalive"),
	}
	pk := getOneOfN(u.Params, "", "privatekey", "pk")
	if pk == "" {
		pk = u.Username
	}
	// Guard against the malformed query form pk=KEY@host:port where '@host:port'
	// leaks into the private_key value (and leaves peer.Address/Port empty).
	if i := strings.IndexByte(pk, '@'); i >= 0 {
		pk = pk[:i]
	}
	if pk == "" {
		return nil, errors.New("missing private_key")
	}
	if peer.PublicKey == "" {
		return nil, errors.New("missing peer_public_key")
	}
	// Without a valid peer endpoint the tunnel is dead — fail loudly instead of
	// emitting a config with an empty endpoint.
	if peer.Address == "" || peer.Port == 0 {
		return nil, errors.New("missing peer endpoint (host:port)")
	}
	if pk, err = normalizeWgKey("private_key", pk); err != nil {
		return nil, err
	}
	if peer.PublicKey, err = normalizeWgKey("peer_public_key", peer.PublicKey); err != nil {
		return nil, err
	}
	if peer.PresharedKey, err = normalizeWgKey("preshared_key", peer.PresharedKey); err != nil {
		return nil, err
	}
	// Cloudflare/WARP 3-byte reserved (comma-separated). Applied in the bind at
	// send time since WireGuard's UAPI has no reserved key.
	if reservedStr, ok := u.Params["reserved"]; ok {
		reserved, err := parseReservedList(reservedStr)
		if err != nil {
			return nil, err
		}
		peer.Reserved = reserved
	}
	opts := T.AwgEndpointOptions{

		PrivateKey: pk,
		Address:    addresses,

		Jc:   clampAwgInt("jc", getInt("jc"), 1),
		Jmin: clampAwgInt("jmin", getInt("jmin"), 1),
		Jmax: clampAwgInt("jmax", getInt("jmax"), 1),

		S1: clampAwgInt("s1", getInt("s1"), 0),
		S2: clampAwgInt("s2", getInt("s2"), 0),
		S3: clampAwgInt("s3", getInt("s3"), 0),
		S4: clampAwgInt("s4", getInt("s4"), 0),
		H1: getOneOfN(u.Params, "", "h1"),
		H2: getOneOfN(u.Params, "", "h2"),
		H3: getOneOfN(u.Params, "", "h3"),
		H4: getOneOfN(u.Params, "", "h4"),

		I1: getOneOfN(u.Params, "", "i1"),
		I2: getOneOfN(u.Params, "", "i2"),
		I3: getOneOfN(u.Params, "", "i3"),
		I4: getOneOfN(u.Params, "", "i4"),
		I5: getOneOfN(u.Params, "", "i5"),

		// AmneziaWG 1.5 controlled-junk generators + inter-handshake timeout.
		J1:    getOneOfN(u.Params, "", "j1"),
		J2:    getOneOfN(u.Params, "", "j2"),
		J3:    getOneOfN(u.Params, "", "j3"),
		Itime: clampAwgInt("itime", getInt("itime"), 0),

		Peers: []T.AwgPeerOptions{peer},
	}
	for _, h := range []struct{ name, spec string }{{"h1", opts.H1}, {"h2", opts.H2}, {"h3", opts.H3}, {"h4", opts.H4}} {
		if err := validateMagicHeader(h.name, h.spec); err != nil {
			return nil, err
		}
	}
	for _, i := range []struct{ name, spec string }{{"i1", opts.I1}, {"i2", opts.I2}, {"i3", opts.I3}, {"i4", opts.I4}, {"i5", opts.I5}} {
		if err := validateObfSpec(i.name, i.spec); err != nil {
			return nil, err
		}
	}
	if mtuStr, ok := u.Params["mtu"]; ok {
		if mtu, err := strconv.ParseUint(mtuStr, 10, 32); err == nil {
			opts.MTU = uint32(mtu)
		}
	}
	var out *T.Endpoint
	// isPlainWG is true when NO AmneziaWG obfs params are present — i.e. this is a
	// plain WireGuard endpoint and must NOT be emitted as type "awg".
	isPlainWG := opts.Jc+opts.Jmin+opts.Jmax+opts.S1+opts.S2+opts.S3+opts.S4+opts.Itime == 0 && opts.H1+opts.H2+opts.H3+opts.H4+opts.I1+opts.I2+opts.I3+opts.I4+opts.I5+opts.J1+opts.J2+opts.J3 == ""

	if isPlainWG {
		wgopts := T.WireGuardEndpointOptions{
			PrivateKey: opts.PrivateKey,
			Address:    opts.Address,
			Peers: []T.WireGuardPeer{
				T.WireGuardPeer{
					Address:                     peer.Address,
					Port:                        peer.Port,
					PreSharedKey:                peer.PresharedKey,
					PublicKey:                   peer.PublicKey,
					AllowedIPs:                  peer.AllowedIPs,
					PersistentKeepaliveInterval: peer.PersistentKeepaliveInterval,
				},
			},
			// Only set MTU when explicitly given; let sing-box apply its native
			// WG default otherwise (do not pin 1280).
			Noise: getWireGuardNoise(u.Params, false),
		}
		// Guarded ParseUint (same pattern as the awg branch above): the old
		// uint32(toInt(mtu)) silently wrapped "-1" into 4294967295.
		if mtuStr := getOneOfN(u.Params, "", "mtu"); mtuStr != "" {
			if mtu, err := strconv.ParseUint(mtuStr, 10, 32); err == nil {
				wgopts.MTU = uint32(mtu)
			}
		}
		if reservedStr, ok := u.Params["reserved"]; ok {
			reserved, err := parseReservedList(reservedStr)
			if err != nil {
				return nil, err
			}
			wgopts.Peers[0].Reserved = reserved
		}
		if workerStr, ok := u.Params["workers"]; ok {
			// Only a positive count is usable: wireguard-go special-cases only
			// workers == 0 (-> NumCPU) and a negative value drives
			// queue.encryption.wg.Add(workers) into a WaitGroup panic at Start.
			if workers, err := strconv.Atoi(workerStr); err == nil && workers > 0 {
				wgopts.Workers = workers
			} else {
				skip("wireguard", "dropping workers="+workerStr+": want a positive integer")
			}
		}
		out = &T.Endpoint{
			Type:    C.TypeWireGuard,
			Tag:     u.Name,
			Options: &wgopts,
		}
		if out.Tag == "" {
			out.Tag = "WG"
		}
	} else {
		out = &T.Endpoint{
			Type:    C.TypeAwg,
			Tag:     u.Name,
			Options: &opts,
		}
		if out.Tag == "" {
			out.Tag = "AWG"
		}
	}

	return out, nil
}
