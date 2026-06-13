package ray2sing

import (
	C "github.com/sagernet/sing-box/constant"
	T "github.com/sagernet/sing-box/option"
)

func WarpSingbox(url string) (*T.Endpoint, error) {
	u, err := ParseUrl(url, 0)
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
			PrivateKey: getOneOfN(u.Params, "", "privatekey", "pk"),
		},
	}
	// Set MTU only when explicitly given; let the core apply its native default
	// otherwise (do not pin 1280).
	if mtu := getOneOfN(u.Params, "", "mtu"); mtu != "" {
		warpOpts.MTU = uint32(toInt(mtu))
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
