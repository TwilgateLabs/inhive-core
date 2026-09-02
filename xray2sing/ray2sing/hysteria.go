package ray2sing

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func HysteriaSingbox(hysteriaURL string) (*T.Outbound, error) {
	u, err := ParseUrl(hysteriaURL, 443)
	if err != nil {
		return nil, err
	}
	SNI := u.Params["peer"]
	opts := T.HysteriaOutboundOptions{
		ServerOptions: u.GetServerOption(),
		OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
			TLS: &T.OutboundTLSOptions{
				Enabled:    true,
				DisableSNI: isIPOnly(SNI),
				ServerName: SNI,
				Insecure:   toBool(u.Params["insecure"], false),
			},
		},
	}
	singOut := &T.Outbound{
		Type:    u.Scheme,
		Tag:     u.Name,
		Options: &opts,
	}

	// alpn is an official Hysteria1 URI param (default "hysteria"); a custom
	// value must reach TLS.ALPN or the QUIC client falls back to DefaultALPN.
	if alpn := getOneOfN(u.Params, "", "alpn"); alpn != "" {
		opts.TLS.ALPN = strings.Split(alpn, ",")
	}

	opts.AuthString = u.Params["auth"]

	upMbps, err := strconv.Atoi(u.Params["upmbps"])
	if err == nil {
		opts.UpMbps = upMbps
	}

	downMbps, err := strconv.Atoi(u.Params["downmbps"])
	if err == nil {
		opts.DownMbps = downMbps
	}

	opts.Obfs = getOneOfN(u.Params, "", "obfsparam", "obfs")

	// port hopping (mport/ports) — sing-box hysteria v1 supports server_ports
	if mp := getOneOfN(u.Params, "", "mport", "ports"); mp != "" {
		entries, _ := normalizeHopPorts(mp)
		opts.ServerPorts = badoption.Listable[string](entries)
		opts.HopInterval = badoption.Duration(30 * time.Second)
	}
	// Официальный v1-словарь protocol=udp|wechat-video|faketcp: у sing-box
	// hysteria только UDP-транспорт — не-udp значение строило вечно-мёртвую
	// UDP-ноду молча. Честная ошибка.
	if proto := strings.ToLower(getOneOfN(u.Params, "", "protocol")); proto != "" && proto != "udp" {
		return nil, fmt.Errorf("hysteria protocol %q is not supported by the sing-box core (udp only)", proto)
	}
	// opts.TurnRelay, err = u.GetRelayOptions()
	if err != nil {
		return nil, err
	}
	return singOut, nil
}
