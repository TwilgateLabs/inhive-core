package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// UTProtoSingbox парсит InHive-схему utproto:// в ПАРУ outbound'ов,
// семантически идентичную Dart-билдеру
// (app/lib/features/proxy/data/singbox_config_builder.dart `_utprotoOutbounds`):
//
//	utproto://SECRET@HOST:PORT?tls_domain=DOMAIN&vless_uuid=UUID&vless_port=19999#Name
//
//	[main]   vless   → server=HOST, server_port=vless_port, uuid=vless_uuid,
//	                   detour=<helper>  (плоский vless: TLS обеспечивает туннель
//	                   utproto, поэтому у самого vless НЕТ tls/transport — 1:1 с
//	                   Dart, который эмитит только type/tag/server/server_port/
//	                   uuid/detour).
//	[helper] utproto → server=HOST, server_port=PORT, secret=SECRET,
//	                   tls_domain=DOMAIN  (FakeTLS+obfuscated2 транспорт).
//
// Возвращает (main, helper). detour здесь ставится на БАЗОВЫЙ helper-тег;
// финальную линковку и уникализацию тегов в живом боксе доделывают вызывающие:
//   - GenerateConfigLite (convert.go): суффиксует оба тега counter'ом и
//     переставляет main.detour на суффиксованный helper-тег;
//   - hcore.AddOutbound: при hot-add переписывает helper-тег поверх уникального
//     mainTag (counter сбрасывается на каждый вызов — cross-call уникальности
//     он не даёт, а два резидента-utproto из одного саба обязаны иметь разные
//     helper-теги).
//
// UTProto — наш протокол (можно менять); ray2sing раньше его не знал, из-за
// чего AddOutbound(content: utproto://…) падал с «unable to determine config
// format» (device-log diag146, 2026-07-22).
func UTProtoSingbox(utprotoURL string) (*T.Outbound, *T.Outbound, error) {
	u, err := ParseUrl(utprotoURL, 443)
	if err != nil {
		return nil, nil, err
	}
	secret := u.Username
	if secret == "" {
		return nil, nil, E.New("utproto: secret (userinfo) is required")
	}
	decoded := u.Params
	// getOneOfN нормализует ключ запроса (normalizeStr: '_'/'-' → пробел,
	// lowercase), поэтому "vless_uuid"/"tls_domain"/"vless_port" находятся.
	vlessUUID := getOneOfN(decoded, "", "vless_uuid")
	if vlessUUID == "" {
		return nil, nil, E.New("utproto: vless_uuid is required")
	}
	// Дефолты 1:1 с Dart-билдером: vless_port=19999, tls_domain=learn.microsoft.com.
	vlessPort := toUInt16(getOneOfN(decoded, "", "vless_port"), 19999)
	tlsDomain := getOneOfN(decoded, "learn.microsoft.com", "tls_domain")

	mainTag := u.Name
	if mainTag == "" {
		mainTag = u.Hostname
	}
	helperTag := "utproto-" + mainTag

	main := &T.Outbound{
		Tag:  mainTag,
		Type: "vless",
		Options: &T.VLESSOutboundOptions{
			DialerOptions: T.DialerOptions{Detour: helperTag},
			ServerOptions: T.ServerOptions{Server: u.Hostname, ServerPort: vlessPort},
			UUID:          vlessUUID,
		},
	}
	helper := &T.Outbound{
		Tag:  helperTag,
		Type: "utproto",
		Options: &T.UTProtoOutboundOptions{
			ServerOptions: T.ServerOptions{Server: u.Hostname, ServerPort: u.Port},
			Secret:        secret,
			TLSDomain:     tlsDomain,
		},
	}
	return main, helper, nil
}
