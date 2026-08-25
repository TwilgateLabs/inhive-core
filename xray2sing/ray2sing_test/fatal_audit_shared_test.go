package ray2sing_test

// Тесты фиксов fatal-аудита 2026-08-25 (shared-обвязка: common.go, url_schema.go,
// convert.go, xhttp_extra.go). Каждый кейс — реальный словарь чужих ссылок,
// который до фикса убивал узел на создании аутбаунда (или весь профиль).

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/twilgate/xray2sing/ray2sing"
)

const sharedUUID = "11111111-2222-3333-4444-555555555555"

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

func sharedParse(t *testing.T, link string) *option.Outbound {
	t.Helper()
	opts, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), link, false)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(opts.Outbounds) == 0 {
		t.Fatalf("no outbounds parsed")
	}
	return &opts.Outbounds[0]
}

func vlessOpts(t *testing.T, o *option.Outbound) *option.VLESSOutboundOptions {
	t.Helper()
	vo, ok := o.Options.(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("not vless options: %T", o.Options)
	}
	return vo
}

// muxtype=none / Smux / h2 — чужой словарь; sing-mux принимает только
// exact-case ""/h2mux/smux/yamux и убивал узел на создании.
func TestMuxTypeForeignVocabulary(t *testing.T) {
	base := "vless://" + sharedUUID + "@example.com:443?security=tls&type=tcp&muxtype="
	if vo := vlessOpts(t, sharedParse(t, base+"none#a")); vo.Multiplex != nil {
		t.Fatalf("muxtype=none must disable mux, got %+v", vo.Multiplex)
	}
	if vo := vlessOpts(t, sharedParse(t, base+"Smux#b")); vo.Multiplex == nil || vo.Multiplex.Protocol != "smux" {
		t.Fatalf("muxtype=Smux must normalize to smux, got %+v", vo.Multiplex)
	}
	if vo := vlessOpts(t, sharedParse(t, base+"h2#c")); vo.Multiplex == nil || vo.Multiplex.Protocol != "h2mux" {
		t.Fatalf("muxtype=h2 must alias to h2mux, got %+v", vo.Multiplex)
	}
}

// muxup=0 (или мусор) при включённом mux давал Brutal с 0 Mbps — гарантированная
// ошибка «brutal: invalid upload speed» на создании.
func TestBrutalZeroSpeedDisabled(t *testing.T) {
	link := "vless://" + sharedUUID + "@example.com:443?security=tls&type=tcp&muxtype=h2mux&muxup=0&muxdown=100#t"
	vo := vlessOpts(t, sharedParse(t, link))
	if vo.Multiplex == nil {
		t.Fatalf("mux must stay enabled")
	}
	if vo.Multiplex.Brutal != nil {
		t.Fatalf("brutal must be disabled on zero speed, got %+v", vo.Multiplex.Brutal)
	}
}

// fp=none (mihomo 'client-fingerprint: none') убивал узел на
// «unknown uTLS fingerprint: none».
func TestFingerprintNoneDisablesUTLS(t *testing.T) {
	vo := vlessOpts(t, sharedParse(t, "vless://"+sharedUUID+"@example.com:443?security=tls&type=tcp&fp=none#t"))
	if vo.TLS == nil || vo.TLS.UTLS != nil {
		t.Fatalf("fp=none must yield std TLS without uTLS, got %+v", vo.TLS)
	}
}

// pbk в std-base64 ('+'/'='), sid длиннее 16 hex: первое sing-box отвергал
// (RawURLEncoding-only), второе ПАНИКОВАЛО в hex.Decode и клало весь профиль.
func TestRealityKeyNormalization(t *testing.T) {
	link := "vless://" + sharedUUID + "@1.2.3.4:443?security=reality&pbk=SOsUxWNQ0zNq6cyYcNCFPMr9Ojm%2BCLM6bMWvHkZDrDQ%3D&sid=001122334455667788&fp=chrome&type=tcp#t"
	vo := vlessOpts(t, sharedParse(t, link))
	if vo.TLS == nil || vo.TLS.Reality == nil {
		t.Fatalf("reality block missing")
	}
	if strings.ContainsAny(vo.TLS.Reality.PublicKey, "+/=") {
		t.Fatalf("pbk must be url-safe unpadded, got %q", vo.TLS.Reality.PublicKey)
	}
	if vo.TLS.Reality.ShortID != "" {
		t.Fatalf("overlong sid must be dropped (it panicked hex.Decode), got %q", vo.TLS.Reality.ShortID)
	}
}

// alpn=h3 на reality-ссылке резал uTLS → «uTLS is required by reality client».
func TestRealityWithH3ALPNKeepsUTLS(t *testing.T) {
	link := "vless://" + sharedUUID + "@1.2.3.4:443?security=reality&pbk=SOsUxWNQ0zNq6cyYcNCFPMr9OjmZCLM6bMWvHkZDrDQ&sid=0123&alpn=h3&type=tcp#t"
	vo := vlessOpts(t, sharedParse(t, link))
	if vo.TLS == nil || vo.TLS.UTLS == nil || !vo.TLS.UTLS.Enabled {
		t.Fatalf("reality must keep uTLS even with alpn=h3, got %+v", vo.TLS)
	}
	if len(vo.TLS.ALPN) != 0 {
		t.Fatalf("useless h3 ALPN must be dropped under reality, got %v", vo.TLS.ALPN)
	}
}

// minVersion=tls1.2 — чужое написание; verbatim оно давало «unknown tls version».
func TestTLSVersionNormalization(t *testing.T) {
	vo := vlessOpts(t, sharedParse(t, "vless://"+sharedUUID+"@example.com:443?security=tls&type=tcp&minVersion=tls1.2&maxVersion=TLSv1.3#t"))
	if vo.TLS.MinVersion != "1.2" || vo.TLS.MaxVersion != "1.3" {
		t.Fatalf("tls versions not normalized: min=%q max=%q", vo.TLS.MinVersion, vo.TLS.MaxVersion)
	}
	vo2 := vlessOpts(t, sharedParse(t, "vless://"+sharedUUID+"@example.com:443?security=tls&type=tcp&minVersion=1.2.0#t"))
	if vo2.TLS.MinVersion != "" {
		t.Fatalf("garbage tls version must be dropped, got %q", vo2.TLS.MinVersion)
	}
}

// ech=0 включал ECH самим фактом наличия ключа; ech=enabled уезжал в PEM и
// давал «invalid ECH configs pem» на создании.
func TestECHValueChecked(t *testing.T) {
	vo := vlessOpts(t, sharedParse(t, "vless://"+sharedUUID+"@example.com:443?security=tls&type=tcp&ech=0#t"))
	if vo.TLS.ECH != nil {
		t.Fatalf("ech=0 must not enable ECH, got %+v", vo.TLS.ECH)
	}
	vo2 := vlessOpts(t, sharedParse(t, "vless://"+sharedUUID+"@example.com:443?security=tls&type=tcp&ech=enabled#t"))
	if vo2.TLS.ECH != nil {
		t.Fatalf("non-base64 ech blob must be dropped, got %+v", vo2.TLS.ECH)
	}
}

// ws path с литеральным '%' — Xray принимает его как опак; url.Parse ронял
// целую ссылку.
func TestWSPathBadEscapeSurvives(t *testing.T) {
	link := "vless://" + sharedUUID + "@example.com:443?security=tls&type=ws&path=%2Fws%25zz#t"
	vo := vlessOpts(t, sharedParse(t, link))
	if vo.Transport == nil || vo.Transport.WebsocketOptions.Path == "" {
		t.Fatalf("ws node with odd path must survive, got %+v", vo.Transport)
	}
}

// net=quic без TLS — sing-box так не умеет (ErrTLSRequired на Start); должна
// быть парс-ошибка на ссылку (skip строки), а не мёртвый узел. Проверяем, что
// в смешанной подписке остальные строки выживают.
func TestLegacyQUICWithoutTLSSkipsLine(t *testing.T) {
	good := "vless://" + sharedUUID + "@example.com:443?security=tls&type=tcp#good"
	// vmess-JSON c net=quic и tls=""
	badJSON := `{"v":"2","ps":"bad","add":"example.com","port":"443","id":"` + sharedUUID + `","aid":"0","net":"quic","type":"none","tls":""}`
	bad := "vmess://" + b64(badJSON)
	opts, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), good+"\n"+bad, false)
	if err != nil {
		t.Fatalf("mixed subscription must survive: %v", err)
	}
	if len(opts.Outbounds) != 1 {
		t.Fatalf("expected 1 surviving outbound, got %d", len(opts.Outbounds))
	}
}

// Тотальный фейл конвертации раньше возвращал строку "null" c err=nil.
func TestRay2SingboxPropagatesTotalFailure(t *testing.T) {
	out, err := ray2sing.Ray2Singbox(libbox.BaseContext(nil), "totally-not-a-config", false)
	if err == nil {
		t.Fatalf("total parse failure must return error, got out=%q err=nil", string(out))
	}
}

// xhttp extra c Xray-словарём (domainStrategy=UseIP, числа строками) целиком
// ронял ссылку; теперь узел живёт, словарь нормализуется.
func TestXHTTPExtraXrayVocabulary(t *testing.T) {
	link := "vless://" + sharedUUID + "@example.com:443?security=tls&type=xhttp&path=%2F&extra=%7B%22domainStrategy%22%3A%22UseIP%22%2C%22scMaxBufferedPosts%22%3A%2230%22%7D#t"
	vo := vlessOpts(t, sharedParse(t, link))
	if vo.Transport == nil || vo.Transport.Type != "xhttp" {
		t.Fatalf("xhttp node must survive extra with Xray vocab, got %+v", vo.Transport)
	}
}

// vmess-JSON без "net", но с "type":"none" (headerType) давал
// «unknown transport type: none» и терял узел.
func TestVmessHeaderTypeNotTransport(t *testing.T) {
	j := `{"v":"2","ps":"t","add":"example.com","port":"443","id":"` + sharedUUID + `","aid":"0","type":"none","tls":""}`
	o := sharedParse(t, "vmess://"+b64(j))
	vm, ok := o.Options.(*option.VMessOutboundOptions)
	if !ok {
		t.Fatalf("not vmess: %T", o.Options)
	}
	if vm.Transport != nil {
		t.Fatalf("type=none must mean plain tcp, got transport %+v", vm.Transport)
	}
}
