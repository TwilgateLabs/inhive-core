package ray2sing

import (
	"strconv"

	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func WarpSingbox(url string) (*T.Endpoint, error) {
	u, err := ParseUrl(url, 0)
	if err != nil {
		return nil, err
	}
	// Same 32-byte base64 contract as any WG key; validated here so a broken
	// profile key fails this one link with a named error instead of dying at
	// endpoint start. Empty is fine — the core registers an anonymous account.
	profileKey, err := normalizeWgKey("privatekey", getOneOfN(u.Params, "", "privatekey", "pk"))
	if err != nil {
		return nil, err
	}
	// fmt.Println(u.Username, "-", u.Password, "-", u.Params)
	warpOpts := &T.WireGuardWARPEndpointOptions{
		ServerOptions: T.ServerOptions{
			Server:     u.Hostname,
			ServerPort: u.Port,
		},
		UniqueIdentifier: u.Username,
		Noise:            getWireGuardNoise(u.Params, false),
		// WARP+ credentials: without license/auth_token the core falls back to an
		// anonymous free account, losing the WARP+ priority/speed.
		Profile: T.WARPProfile{
			License:    getOneOfN(u.Params, "", "license", "key"),
			ID:         getOneOfN(u.Params, "", "id", "deviceid"),
			AuthToken:  getOneOfN(u.Params, "", "token", "authtoken"),
			PrivateKey: profileKey,
		},
	}
	// Set MTU only when explicitly given; let the core apply its native default
	// otherwise (do not pin 1280). Guarded ParseUint — uint32(toInt(...))
	// silently wrapped negative/overflow values.
	if mtuStr := getOneOfN(u.Params, "", "mtu"); mtuStr != "" {
		if mtu, err := strconv.ParseUint(mtuStr, 10, 32); err == nil {
			warpOpts.MTU = uint32(mtu)
		}
	}
	out := T.Endpoint{
		Type:    C.TypeWARP,
		Tag:     u.Name,
		Options: warpOpts,
	}

	if out.Tag == "" {
		out.Tag = "WARP"
	}
	return &out, nil
}
