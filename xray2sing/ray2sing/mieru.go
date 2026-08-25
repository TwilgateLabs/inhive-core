package ray2sing

import (
	"fmt"
	"strings"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

func MieruSingbox(uri string) (*T.Outbound, error) {
	u, err := ParseUrl(uri, 0)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// mierus://baozi:manlianpenfen@1.2.3.4?handshake-mode=HANDSHAKE_NO_WAIT&mtu=1400&multiplexing=MULTIPLEXING_HIGH&port=6666&port=9998-9999&port=6489&port=4896&profile=default&protocol=TCP&protocol=TCP&protocol=UDP&protocol=UDP
	// https://github.com/enfein/mieru/blob/main/docs/client-install.md#simple-sharing-link
	protocols := strings.Split(getOneOfN(decoded, "", "protocol"), ",")
	// A missing ?protocol= yields [""], and getTransportProtocol("") is nil ->
	// "transport must be TCP or UDP" at creation, killing the minimal
	// mierus://user:pass@host:6666 link the authority-port fallback below
	// explicitly supports. Default every empty element (fully-absent param AND
	// stray "TCP," trailing-empty case) to mieru's primary transport, TCP.
	for i, p := range protocols {
		if strings.TrimSpace(p) == "" {
			protocols[i] = "TCP"
		}
	}
	// Port may live only in the authority (mierus://a:b@host:6666?protocol=TCP)
	// with no ?port= query. In that case fill one authority port per protocol;
	// otherwise sing-box fails with "either port or port_range must be set".
	var ports []string
	if portParam := getOneOfN(decoded, "", "port"); portParam == "" && u.Port != 0 {
		ports = make([]string, len(protocols))
		for i := range ports {
			ports[i] = fmt.Sprintf("%d", u.Port)
		}
	} else {
		ports = strings.Split(portParam, ",")
		if len(protocols) == len(ports)+1 {
			ports = append([]string{fmt.Sprintf("%d", u.Port)}, ports...)
		}
	}
	if len(protocols) != len(ports) {
		return nil, E.New("the number of protocols must be the same as the number of ports")
	}
	transports := make([]option.MieruPortBinding, len(protocols))
	for i := 0; i < len(protocols); i++ {
		transports[i] = option.MieruPortBinding{
			Protocol: protocols[i],
		}
		if strings.Contains(ports[i], "-") {
			transports[i].PortRange = ports[i]
		} else {
			transports[i].Port = toUInt16(ports[i], 0)
		}
	}
	result := T.Outbound{
		Type: C.TypeMieru,
		Tag:  u.Name,
		Options: &T.MieruOutboundOptions{
			DialerOptions: getDialerOptions(decoded),
			ServerOptions: T.ServerOptions{
				Server: u.Hostname,
			},
			UserName:      u.Username,
			Password:      u.Password,
			PortBindings:  transports,
			Multiplexing:  getOneOfN(decoded, "", "multiplexing"),
			HandshakeMode: getOneOfN(decoded, "", "handshake-mode", "handshakemode"),
			// Official mieru sharing-link param. The pinned mieru v3 library
			// enforces range [1280,1500] at config store time and REJECTS the
			// whole client config otherwise (node dead at creation), so an
			// out-of-range value (mtu=1200 WireGuard intuition, mtu=9000 jumbo)
			// is dropped to 0 = library default instead of passed through.
			MTU: clampMieruMTU(toInt(getOneOfN(decoded, "", "mtu"))),
		},
	}

	return &result, nil
}

// clampMieruMTU drops MTU values outside the mieru library's accepted range
// [1280,1500] (mieru/v3 appctlcommon: "MTU value %d is out of range") back to
// 0, which keeps the library default rather than killing the node at creation.
func clampMieruMTU(mtu int) int32 {
	if mtu != 0 && (mtu < 1280 || mtu > 1500) {
		return 0
	}
	return int32(mtu)
}
