package ray2sing_test

import (
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	T "github.com/sagernet/sing-box/option"
	"github.com/twilgate/xray2sing/ray2sing"
)

// TestUTProtoPair — одиночная utproto:// ссылка разворачивается в ПАРУ,
// семантически идентичную Dart-билдеру (_utprotoOutbounds): vless-main с
// detour → utproto-helper. Порядок: main ПЕРВЫМ (hcore.AddOutbound берёт
// real[0] как главный).
func TestUTProtoPair(t *testing.T) {
	url := "utproto://0123456789abcdef0123456789abcdef@1.2.3.4:8443?tls_domain=learn.microsoft.com&vless_uuid=761bb14f-51aa-49b6-b583-37ea11132568&vless_port=19999#My UT"

	expectedJSON := `
	{
		"outbounds": [
			{
				"type": "vless",
				"tag": "My UT § 0",
				"server": "1.2.3.4",
				"server_port": 19999,
				"detour": "utproto-My UT § 1",
				"uuid": "761bb14f-51aa-49b6-b583-37ea11132568"
			},
			{
				"type": "utproto",
				"tag": "utproto-My UT § 1",
				"server": "1.2.3.4",
				"server_port": 8443,
				"secret": "0123456789abcdef0123456789abcdef",
				"tls_domain": "learn.microsoft.com"
			}
		]
	}
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}

// TestUTProtoDefaults — при отсутствии vless_port/tls_domain применяются те же
// дефолты, что у Dart-билдера (19999 / learn.microsoft.com).
func TestUTProtoDefaults(t *testing.T) {
	url := "utproto://00112233445566778899aabbccddeeff@example.com:443?vless_uuid=11111111-2222-3333-4444-555555555555#N"

	expectedJSON := `
	{
		"outbounds": [
			{
				"type": "vless",
				"tag": "N § 0",
				"server": "example.com",
				"server_port": 19999,
				"detour": "utproto-N § 1",
				"uuid": "11111111-2222-3333-4444-555555555555"
			},
			{
				"type": "utproto",
				"tag": "utproto-N § 1",
				"server": "example.com",
				"server_port": 443,
				"secret": "00112233445566778899aabbccddeeff",
				"tls_domain": "learn.microsoft.com"
			}
		]
	}
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}

// TestUTProtoMultiUniqueTags — две utproto-ноды в одной подписке: counter
// монотонный по всему парсу, каждый helper-тег уникален, и main.detour каждой
// пары указывает на СВОЙ helper (никакого перекрёстного склеивания).
func TestUTProtoMultiUniqueTags(t *testing.T) {
	sub := strings.Join([]string{
		"utproto://0123456789abcdef0123456789abcdef@1.1.1.1:8443?vless_uuid=761bb14f-51aa-49b6-b583-37ea11132568#A",
		"utproto://ffeeddccbbaa99887766554433221100@2.2.2.2:8443?vless_uuid=11111111-2222-3333-4444-555555555555#B",
	}, "\n")

	opts, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), sub, false)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(opts.Outbounds) != 4 {
		t.Fatalf("expected 4 outbounds (2 pairs), got %d", len(opts.Outbounds))
	}

	detourOf := func(o T.Outbound) string {
		if dw, ok := o.Options.(T.DialerOptionsWrapper); ok {
			return dw.TakeDialerOptions().Detour
		}
		return ""
	}

	// [0]=main A, [1]=helper A, [2]=main B, [3]=helper B (main-first порядок).
	mainA, helperA, mainB, helperB := opts.Outbounds[0], opts.Outbounds[1], opts.Outbounds[2], opts.Outbounds[3]

	if mainA.Type != "vless" || helperA.Type != "utproto" || mainB.Type != "vless" || helperB.Type != "utproto" {
		t.Fatalf("unexpected types: %s/%s/%s/%s", mainA.Type, helperA.Type, mainB.Type, helperB.Type)
	}
	// Уникальность helper-тегов между парами.
	if helperA.Tag == helperB.Tag {
		t.Fatalf("helper tags collide: %q", helperA.Tag)
	}
	// Каждый main указывает на СВОЙ helper.
	if detourOf(mainA) != helperA.Tag {
		t.Errorf("main A detour %q != helper A tag %q", detourOf(mainA), helperA.Tag)
	}
	if detourOf(mainB) != helperB.Tag {
		t.Errorf("main B detour %q != helper B tag %q", detourOf(mainB), helperB.Tag)
	}
	// Никакого перекрёстного detour.
	if detourOf(mainA) == helperB.Tag || detourOf(mainB) == helperA.Tag {
		t.Errorf("cross-wired detour: A→%q B→%q (helperA=%q helperB=%q)",
			detourOf(mainA), detourOf(mainB), helperA.Tag, helperB.Tag)
	}
}

// TestDnsttParse — dnstt:// (ре-добавлен) разбирается в dnstt-outbound с
// полями domain/pubkey/resolver 1:1 с Dart-билдером.
func TestDnsttParse(t *testing.T) {
	url := "dnstt://t.example.com?pubkey=abcdef0123456789&resolver=8.8.8.8:53#DNSTT-1"

	expectedJSON := `
	{
		"outbounds": [
			{
				"type": "dnstt",
				"tag": "DNSTT-1 § 0",
				"domain": "t.example.com",
				"pubkey": "abcdef0123456789",
				"resolver": "8.8.8.8:53"
			}
		]
	}
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
