package ray2sing

import (
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
				pfx, err := netip.ParsePrefix(val)
				if err != nil {
					return nil, fmt.Errorf("invalid AllowedIPs: %w", err)
				}
				peer.AllowedIPs = badoption.Listable[netip.Prefix]{pfx}

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

	if len(peers) == 0 {
		return nil, errors.New("missing peer Endpoint")
	}
	for i := range peers {
		if peers[i].Address == "" || peers[i].Port == 0 {
			return nil, errors.New("missing peer Endpoint")
		}
		if len(peers[i].AllowedIPs) == 0 {
			peers[i].AllowedIPs = badoption.Listable[netip.Prefix]([]netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
			})
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
			Type:    C.TypeWireGuard,
			Tag:     "wiregaurd",
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
	// Cloudflare/WARP 3-byte reserved (comma-separated). Applied in the bind at
	// send time since WireGuard's UAPI has no reserved key.
	if reservedStr, ok := u.Params["reserved"]; ok {
		for _, part := range strings.Split(reservedStr, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			num, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return nil, err
			}
			peer.Reserved = append(peer.Reserved, uint8(num))
		}
	}
	opts := T.AwgEndpointOptions{

		PrivateKey: pk,
		Address:    addresses,

		Jc:   getInt("jc"),
		Jmin: getInt("jmin"),
		Jmax: getInt("jmax"),

		S1: getInt("s1"),
		S2: getInt("s2"),
		S3: getInt("s3"),
		S4: getInt("s4"),
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
		Itime: getInt("itime"),

		Peers: []T.AwgPeerOptions{peer},
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
		if mtu := getOneOfN(u.Params, "", "mtu"); mtu != "" {
			wgopts.MTU = uint32(toInt(mtu))
		}
		if reservedStr, ok := u.Params["reserved"]; ok {
			reservedParts := strings.Split(reservedStr, ",")
			for _, part := range reservedParts {
				num, err := strconv.ParseUint(part, 10, 8)
				if err != nil {
					return nil, err // Handle the error appropriately
				}
				wgopts.Peers[0].Reserved = append(wgopts.Peers[0].Reserved, uint8(num))
			}
		}
		if workerStr, ok := u.Params["workers"]; ok {
			if workers, err := strconv.Atoi(workerStr); err == nil {
				wgopts.Workers = workers
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
