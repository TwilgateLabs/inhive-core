package config

// parser_singleuri_test.go — табличный гард одиночного parse-пути (root cause
// hot-add EOF, 2026-07-22).
//
// СИМПТОМ. AddOutbound (hot-add в живое ядро) кормит ParseConfig тем же
// контентом, что хранит app как «идентичность сервера»: share-link URI ИЛИ
// одиночный sing-box outbound/endpoint JSON (servers из контейнерных подписок —
// см. app server_uri_parser.dart). Для JSON-класса parseConfigContent падал с
// «[SingboxParser] unmarshal error: EOF»: JSON-ветка оборачивала В СЕБЯ пустую
// карту (jsonObj["outbounds"] = []interface{}{jsonObj} — цикл), MarshalIndent
// молча возвращал nil, и UnmarshalJSONContext(nil) давал EOF. Полная сборка
// при этом работает (coreParse идёт через ray2sing.Ray2Singbox с json_ingest),
// поэтому каждый такой сервер = лишняя пересборка ядра при soft-switch.
//
// КОНТРАКТ, который держит этот тест: всё, что переваривает полная сборка
// подписки (share-link / одиночный sing-box JSON / Xray JSON / SIP008 /
// массив), обязано перевариваться и одиночным ParseConfig — путём AddOutbound.
//
// Запуск (теги обязательны, без них sing-box registry неполон):
//
//	cd core && TAGS=$(sed -n 's/^BASE_TAGS=//p' Makefile|head -1) \
//	  go test -tags "$TAGS" ./v2/config/ -run TestParseSingleServerContent -v

import (
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

type singleServerCase struct {
	name          string
	content       string
	wantOutbounds int
	wantEndpoints int
	wantType      string // тип первого outbound (или endpoint, если outbounds нет)
}

var singleServerCases = []singleServerCase{
	// ── share-link класс (работал и до фикса — гард от регрессии) ──────────
	{
		name:          "vless reality tcp (share-link)",
		content:       "vless://0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9@1.2.3.4:443?security=reality&pbk=eLVH-wqasU5th1LgWxkL82y_wCp1dSApnc_E0kDp40s&sid=6ba85179&fp=chrome&type=tcp&flow=xtls-rprx-vision&encryption=none#NL%20TCP",
		wantOutbounds: 1,
		wantType:      "vless",
	},
	{
		name:          "vless xhttp tls (share-link)",
		content:       "vless://0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9@cdn.example.com:443?security=tls&sni=cdn.example.com&type=xhttp&path=%2Fxh&mode=auto&encryption=none#XHTTP",
		wantOutbounds: 1,
		wantType:      "vless",
	},
	{
		name:          "trojan ws tls (share-link)",
		content:       "trojan://trojanpass@example.com:443?type=ws&path=%2Fws&security=tls&sni=example.com#Trojan%20WS",
		wantOutbounds: 1,
		wantType:      "trojan",
	},
	{
		name:          "shadowsocks (share-link SIP002)",
		content:       "ss://YWVzLTI1Ni1nY206c3NwYXNz@1.2.3.4:8388#SS",
		wantOutbounds: 1,
		wantType:      "shadowsocks",
	},
	{
		name:          "vmess ws (share-link base64)",
		content:       "vmess://eyJ2IjogIjIiLCAicHMiOiAiVk1lc3MgV1MiLCAiYWRkIjogIjUuNi43LjgiLCAicG9ydCI6ICI0NDMiLCAiaWQiOiAiMGExYjJjM2QtNGU1Zi02MDcxLTgyOTMtYTRiNWM2ZDdlOGY5IiwgImFpZCI6ICIwIiwgInNjeSI6ICJhdXRvIiwgIm5ldCI6ICJ3cyIsICJwYXRoIjogIi92bSIsICJob3N0IjogInZtLmV4YW1wbGUuY29tIiwgInRscyI6ICJ0bHMiLCAic25pIjogInZtLmV4YW1wbGUuY29tIn0=",
		wantOutbounds: 1,
		wantType:      "vmess",
	},
	{
		name:          "hysteria2 obfs (share-link)",
		content:       "hysteria2://letmein@1.2.3.4:8443?sni=example.com&alpn=h3&obfs=salamander&obfs-password=obfspass#Hy2",
		wantOutbounds: 1,
		wantType:      "hysteria2",
	},
	{
		name:          "tuic (share-link)",
		content:       "tuic://0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9:tuicpass@1.2.3.4:443?congestion_control=bbr&alpn=h3&sni=example.com#TUIC",
		wantOutbounds: 1,
		wantType:      "tuic",
	},
	// ── одиночный sing-box outbound JSON (класс hot-add EOF — RED до фикса) ─
	{
		name:          "vless ws tls (single sing-box JSON)",
		content:       `{"type":"vless","server":"1.2.3.4","server_port":443,"uuid":"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9","tls":{"enabled":true,"server_name":"example.com"},"transport":{"type":"ws","path":"/ws"}}`,
		wantOutbounds: 1,
		wantType:      "vless",
	},
	{
		name:          "vless reality tcp (single sing-box JSON)",
		content:       `{"type":"vless","server":"1.2.3.4","server_port":443,"uuid":"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"example.com","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"eLVH-wqasU5th1LgWxkL82y_wCp1dSApnc_E0kDp40s","short_id":"6ba85179"}}}`,
		wantOutbounds: 1,
		wantType:      "vless",
	},
	{
		name:          "vless xhttp (single sing-box JSON)",
		content:       `{"type":"vless","server":"cdn.example.com","server_port":443,"uuid":"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9","tls":{"enabled":true,"server_name":"cdn.example.com"},"transport":{"type":"xhttp","path":"/xh","mode":"auto"}}`,
		wantOutbounds: 1,
		wantType:      "vless",
	},
	{
		name:          "trojan grpc (single sing-box JSON)",
		content:       `{"type":"trojan","server":"1.2.3.4","server_port":443,"password":"trojanpass","tls":{"enabled":true,"server_name":"example.com"},"transport":{"type":"grpc","service_name":"svc"}}`,
		wantOutbounds: 1,
		wantType:      "trojan",
	},
	{
		name:          "shadowtls v3 (single sing-box JSON)",
		content:       `{"type":"shadowtls","server":"1.2.3.4","server_port":443,"version":3,"password":"stpass","tls":{"enabled":true,"server_name":"cloud.example.com"}}`,
		wantOutbounds: 1,
		wantType:      "shadowtls",
	},
	{
		name:          "hysteria2 obfs (single sing-box JSON)",
		content:       `{"type":"hysteria2","server":"1.2.3.4","server_port":8443,"password":"letmein","obfs":{"type":"salamander","password":"obfspass"},"tls":{"enabled":true,"server_name":"example.com","alpn":["h3"]}}`,
		wantOutbounds: 1,
		wantType:      "hysteria2",
	},
	{
		name:          "anytls (single sing-box JSON, типа нет в singbox_ingest URI-обходе)",
		content:       `{"type":"anytls","server":"1.2.3.4","server_port":443,"password":"atpass","tls":{"enabled":true,"server_name":"example.com"}}`,
		wantOutbounds: 1,
		wantType:      "anytls",
	},
	{
		name:          "shadowsocks (single sing-box JSON)",
		content:       `{"type":"shadowsocks","server":"1.2.3.4","server_port":8388,"method":"aes-256-gcm","password":"sspass"}`,
		wantOutbounds: 1,
		wantType:      "shadowsocks",
	},
	// ── одиночный sing-box endpoint JSON (wireguard/awg живут в endpoints[]) ─
	{
		name:          "wireguard (single sing-box endpoint JSON)",
		content:       `{"type":"wireguard","address":["172.16.0.2/32"],"private_key":"lkVixBsvwS1FLSKVNOc2rBG+hqiIFVYc8l+5kp5JWtQ=","peers":[{"address":"162.159.192.1","port":2408,"public_key":"xQZfukJm8IeGNMqUlahMNUCAaOAJfWRFDeLkl4M8utw=","allowed_ips":["0.0.0.0/0","::/0"]}]}`,
		wantEndpoints: 1,
		wantType:      "wireguard",
	},
	// ── массив sing-box outbound-объектов ────────────────────────────────────
	{
		name:          "array of sing-box outbounds (JSON)",
		content:       `[{"type":"vless","tag":"a","server":"1.2.3.4","server_port":443,"uuid":"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"},{"type":"trojan","tag":"b","server":"5.6.7.8","server_port":443,"password":"pw","tls":{"enabled":true,"server_name":"example.com"}}]`,
		wantOutbounds: 2,
		wantType:      "vless",
	},
	// ── Xray JSON (канонический coreParse это ест через json_ingest) ────────
	{
		name:          "xray single outbound JSON (protocol vless)",
		content:       `{"protocol":"vless","tag":"proxy","settings":{"vnext":[{"address":"1.2.3.4","port":443,"users":[{"id":"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9","flow":"","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"example.com"},"wsSettings":{"path":"/ws"}}}`,
		wantOutbounds: 1,
		wantType:      "vless",
	},
	{
		name:          "xray full config JSON (outbounds[])",
		content:       `{"log":{"loglevel":"warning"},"outbounds":[{"protocol":"trojan","tag":"proxy","settings":{"servers":[{"address":"1.2.3.4","port":443,"password":"pw"}]},"streamSettings":{"network":"tcp","security":"tls","tlsSettings":{"serverName":"example.com"}}}],"routing":{"rules":[]}}`,
		wantOutbounds: 1,
		wantType:      "trojan",
	},
	// ── SIP008 (Shadowsocks server list) ────────────────────────────────────
	{
		name:          "SIP008 servers list JSON",
		content:       `{"version":1,"servers":[{"server":"1.2.3.4","server_port":8388,"method":"aes-256-gcm","password":"sspass","remarks":"SS Node"}]}`,
		wantOutbounds: 1,
		wantType:      "shadowsocks",
	},
	// ── полный sing-box конфиг (работал и до фикса — гард) ──────────────────
	{
		name:          "full sing-box config (outbounds[] extracted)",
		content:       `{"log":{"level":"warn"},"outbounds":[{"type":"vless","tag":"node","server":"1.2.3.4","server_port":443,"uuid":"0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"}],"route":{"rules":[]}}`,
		wantOutbounds: 1,
		wantType:      "vless",
	},
}

// TestParseSingleServerContent гоняет каждый класс контента через ТОТ ЖЕ вызов,
// что делает AddOutbound (commands.go): ParseConfig с Content и fullConfig=false.
func TestParseSingleServerContent(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	for _, tc := range singleServerCases {
		t.Run(tc.name, func(t *testing.T) {
			opts, err := ParseConfig(ctx, &ReadOptions{Content: tc.content}, false, DefaultInhiveOptions(), false)
			if err != nil {
				t.Fatalf("ParseConfig failed: %v", err)
			}
			if got := len(opts.Outbounds); got != tc.wantOutbounds {
				t.Fatalf("outbounds: got %d, want %d (%+v)", got, tc.wantOutbounds, opts.Outbounds)
			}
			if got := len(opts.Endpoints); got != tc.wantEndpoints {
				t.Fatalf("endpoints: got %d, want %d (%+v)", got, tc.wantEndpoints, opts.Endpoints)
			}
			gotType := ""
			if len(opts.Outbounds) > 0 {
				gotType = opts.Outbounds[0].Type
			} else if len(opts.Endpoints) > 0 {
				gotType = opts.Endpoints[0].Type
			}
			if gotType != tc.wantType {
				t.Fatalf("type: got %q, want %q", gotType, tc.wantType)
			}
		})
	}
}
