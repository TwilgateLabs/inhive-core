package ray2sing

import (
	"net/url"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// DnsttSingbox парсит dnstt:// (DNS-туннель) в dnstt-outbound, семантически
// идентично Dart-билдеру (_dnsttOutbound) и sing-box option.DnsttOutboundOptions:
//
//	dnstt://DOMAIN?pubkey=HEX&resolver=8.8.8.8:53#name
//
//	domain   — зона NS-делегации (host[+path]);
//	pubkey   — Ed25519 сервера (hex);
//	resolver — опциональный DNS-резолвер (UDP "8.8.8.8:53" / DoH / DoT).
//
// Ре-добавлено 2026-07-22: схема снималась 2026-04-19 при дегиддификации
// («re-add with clean upstream wrapper»), но КЛИЕНТСКИЙ dnstt-outbound
// зарегистрирован (sing-box/include/registry.go dnstt.RegisterOutbound), а поля
// 1:1 совпадают с Dart-билдером и option.DnsttOutboundOptions — значит hot-add
// чужой подписки с dnstt-нодой больше не отдаёт «?». Разбираем через url.Parse
// (а не ParseUrl), чтобы domain = host+path точно повторял Dart.
func DnsttSingbox(dnsttURL string) (*T.Outbound, error) {
	parsed, err := url.Parse(dnsttURL)
	if err != nil {
		return nil, err
	}
	// Dart: domain = u.host + u.path (зона может нести суффикс-путь).
	domain := parsed.Hostname() + parsed.EscapedPath()
	if domain == "" {
		return nil, E.New("dnstt: domain is required")
	}
	q := parsed.Query()
	pubkey := q.Get("pubkey")
	if pubkey == "" {
		return nil, E.New("dnstt: pubkey is required")
	}
	name := parsed.Fragment
	if name == "" {
		name = domain
	}
	return &T.Outbound{
		Tag:  name,
		Type: "dnstt",
		Options: &T.DnsttOutboundOptions{
			Domain:   domain,
			Pubkey:   pubkey,
			Resolver: q.Get("resolver"), // "" → sing-box применит дефолт 8.8.8.8:53
		},
	}, nil
}
