package ray2sing_test

// zz_sweep_envelope_test.go — envelope-plumbing sweep (аудит 2026-09-02).
// Область: url_schema.go / spliter.go / convert.go / hb64.go — формы ВХОДА,
// которые эмитят реальные экспортёры (v2rayN, панели, Notepad, `base64 -w`,
// Excel-копипаста) и которые ломают парсинг конверта до всякой протокольной
// семантики. FAILING-тест = подтверждённый баг (оставлен красным намеренно).
// Имена хелперов префиксованы sw*, чтобы не конфликтовать с fatal_audit_*.

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/twilgate/xray2sing/ray2sing"
)

const swUUID = "99999999-8888-7777-6666-555555555555"

func swB64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

// swParseAll конвертит тело подписки и возвращает outbounds (может быть пустым
// слайсом при ошибке — вызывающий сам решает, что ассертить).
func swParseAll(t *testing.T, body string) ([]option.Outbound, error) {
	t.Helper()
	opts, err := ray2sing.Ray2SingboxOptions(libbox.BaseContext(nil), body, false)
	if err != nil {
		return nil, err
	}
	return opts.Outbounds, nil
}

func swVless(name string) string {
	return "vless://" + swUUID + "@example.com:443?security=tls&type=tcp#" + name
}

func swTrojanNoPort(name string) string {
	return "trojan://password123@example.com?security=tls&type=tcp#" + name
}

// ---------------------------------------------------------------------------
// 1. Регистр схемы. RFC 3986 §3.1: scheme case-insensitive. iOS-клавиатура
// автокапитализирует первый символ при ручной вставке ("Vless://"), некоторые
// панели/боты отдают "VMESS://". Диспатч в convert.go:147-158 —
// strings.HasPrefix по lowercase-ключам, а сплиттер (spliter.go:42) — regex без
// (?i): узел с не-lowercase схемой не сплитится и не диспатчится.
// ---------------------------------------------------------------------------

func TestSweepUppercaseScheme(t *testing.T) {
	link := swVless("up")
	for _, variant := range []string{
		"VLESS://" + strings.TrimPrefix(link, "vless://"),
		"Vless://" + strings.TrimPrefix(link, "vless://"),
		"TROJAN://password123@example.com:443?security=tls#up2",
		"SS://" + swB64("aes-256-gcm:pass") + "@example.com:8388#up3",
	} {
		outs, err := swParseAll(t, variant)
		if err != nil || len(outs) != 1 {
			t.Errorf("scheme-case variant %.20q... must parse (RFC 3986 case-insensitive), got outs=%d err=%v", variant, len(outs), err)
		}
	}
}

// В многострочной подписке uppercase-строка ещё и склеивается с предыдущей
// нодой (сплиттер её не видит) — теряется молча.
func TestSweepUppercaseSchemeInList(t *testing.T) {
	body := swVless("a") + "\n" + "VLESS://" + strings.TrimPrefix(swVless("b"), "vless://")
	outs, err := swParseAll(t, body)
	if err != nil {
		t.Fatalf("mixed-case list must parse: %v", err)
	}
	if len(outs) != 2 {
		t.Errorf("expected 2 outbounds (uppercase line silently lost), got %d", len(outs))
	}
}

// ---------------------------------------------------------------------------
// 2. UTF-8 BOM. Windows Notepad / PowerShell Out-File пишут BOM; юзер сохраняет
// подписку в файл и импортирует. strings.TrimSpace НЕ снимает U+FEFF
// (unicode.IsSpace(U+FEFF)=false), поэтому:
//  - plain-список: сплиттер (?m)^vless:// не матчит первую строку → первая
//    нода теряется (одиночная — весь импорт «No outbounds found»);
//  - base64-тело: BOM ломает decodeBase64FaultTolerant (hb64.go:31 TrimSpace
//    бессилен) → тело вообще не декодится.
// (convertAWGConfEntries BOM снимает — convert.go:484 — а общий вход нет.)
// ---------------------------------------------------------------------------

func TestSweepBOMPlainSingle(t *testing.T) {
	outs, err := swParseAll(t, "\uFEFF"+swVless("bom"))
	if err != nil || len(outs) != 1 {
		t.Errorf("BOM-prefixed single link must parse, got outs=%d err=%v", len(outs), err)
	}
}

func TestSweepBOMPlainList(t *testing.T) {
	body := "\uFEFF" + swVless("a") + "\n" + swVless("b")
	outs, err := swParseAll(t, body)
	if err != nil {
		t.Fatalf("BOM list must parse: %v", err)
	}
	if len(outs) != 2 {
		t.Errorf("expected 2 outbounds (first line eaten by BOM), got %d", len(outs))
	}
}

func TestSweepBOMBase64Body(t *testing.T) {
	body := "\uFEFF" + swB64(swVless("a")+"\n"+swVless("b"))
	outs, err := swParseAll(t, body)
	if err != nil || len(outs) != 2 {
		t.Errorf("BOM before base64 body must still decode, got outs=%d err=%v", len(outs), err)
	}
}

// ---------------------------------------------------------------------------
// 3. Line-wrapped base64. `base64` (coreutils) по умолчанию заворачивает на 76
// колонок; e-mail/MIME — тоже; часть панелей отдаёт wrapped-тело. Go-декодер
// игнорирует \r\n ВНУТРИ, но паддинг-математика hb64.go:32 (len(raw)%4) считает
// переводы строк как данные → добивает лишние '=' → decode падает → тело
// шинкуется построчно на бинарные огрызки.
// ---------------------------------------------------------------------------

func TestSweepWrappedBase64(t *testing.T) {
	plain := swVless("wrapped-a") + "\n" + swVless("wrapped-b")
	enc := swB64(plain)
	for _, tc := range []struct {
		name  string
		width int
		nl    string
	}{
		{"mime76-crlf", 76, "\r\n"},
		{"w64-lf", 64, "\n"},
		{"w60-lf", 60, "\n"},
	} {
		var sb strings.Builder
		for i := 0; i < len(enc); i += tc.width {
			end := i + tc.width
			if end > len(enc) {
				end = len(enc)
			}
			sb.WriteString(enc[i:end])
			sb.WriteString(tc.nl)
		}
		outs, err := swParseAll(t, sb.String())
		if err != nil || len(outs) != 2 {
			t.Errorf("%s: wrapped base64 must decode to 2 nodes, got outs=%d err=%v", tc.name, len(outs), err)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Regression guards — формы, которые СЕЙЧАС работают (не удалять: это
// контракт конверта).
// ---------------------------------------------------------------------------

// CRLF plain-список (Windows-панели, notepad).
func TestSweepCRLFPlainList(t *testing.T) {
	body := swVless("a") + "\r\n" + swVless("b") + "\r\n"
	outs, err := swParseAll(t, body)
	if err != nil || len(outs) != 2 {
		t.Errorf("CRLF list must parse, got outs=%d err=%v", len(outs), err)
	}
}

// base64-тело, внутри которого CRLF-разделители.
func TestSweepCRLFInsideBase64(t *testing.T) {
	body := swB64(swVless("a") + "\r\n" + swVless("b"))
	outs, err := swParseAll(t, body)
	if err != nil || len(outs) != 2 {
		t.Errorf("base64(CRLF list) must parse, got outs=%d err=%v", len(outs), err)
	}
}

// URL-safe unpadded base64-конверт (некоторые панели кодируют base64url).
func TestSweepURLSafeUnpaddedBase64(t *testing.T) {
	plain := swVless("a") + "\n" + swVless("b")
	enc := base64.RawURLEncoding.EncodeToString([]byte(plain))
	outs, err := swParseAll(t, enc)
	if err != nil || len(outs) != 2 {
		t.Errorf("base64url unpadded body must parse, got outs=%d err=%v", len(outs), err)
	}
}

// Пустые строки, комментарии, хвостовые пробелы на строке.
func TestSweepBlankLinesCommentsTrailingWS(t *testing.T) {
	body := "\n\n# comment\n" + swVless("a") + "   \n\n// another\n" + swVless("b") + "\t\n"
	outs, err := swParseAll(t, body)
	if err != nil || len(outs) != 2 {
		t.Errorf("blank/comment/trailing-ws list must yield 2, got outs=%d err=%v", len(outs), err)
	}
}

// IPv6-литерал в хосте.
func TestSweepIPv6LiteralHost(t *testing.T) {
	link := "vless://" + swUUID + "@[2001:db8::1]:8443?security=tls&type=tcp#v6"
	outs, err := swParseAll(t, link)
	if err != nil || len(outs) != 1 {
		t.Fatalf("IPv6 literal must parse, got outs=%d err=%v", len(outs), err)
	}
	vo, ok := outs[0].Options.(*option.VLESSOutboundOptions)
	if !ok {
		t.Fatalf("not vless: %T", outs[0].Options)
	}
	if vo.Server != "2001:db8::1" || vo.ServerPort != 8443 {
		t.Errorf("IPv6 host/port mangled: server=%q port=%d", vo.Server, vo.ServerPort)
	}
}

// Percent-encoded ':' '@' и литеральный '+' в userinfo (trojan-пароль).
func TestSweepUserinfoEscapesAndPlus(t *testing.T) {
	link := "trojan://p%40ss%3Aw%2Frd@example.com:443?security=tls#u1"
	outs, err := swParseAll(t, link)
	if err != nil || len(outs) != 1 {
		t.Fatalf("escaped userinfo must parse, got outs=%d err=%v", len(outs), err)
	}
	to, ok := outs[0].Options.(*option.TrojanOutboundOptions)
	if !ok {
		t.Fatalf("not trojan: %T", outs[0].Options)
	}
	if to.Password != "p@ss:w/rd" {
		t.Errorf("escaped password mangled: %q", to.Password)
	}

	link2 := "trojan://pass+word@example.com:443?security=tls#u2"
	outs2, err := swParseAll(t, link2)
	if err != nil || len(outs2) != 1 {
		t.Fatalf("plus-in-userinfo must parse, got outs=%d err=%v", len(outs2), err)
	}
	to2 := outs2[0].Options.(*option.TrojanOutboundOptions)
	if to2.Password != "pass+word" {
		t.Errorf("literal '+' in userinfo must stay '+' (no form-decoding), got %q", to2.Password)
	}
}

// Фрагмент с пробелами и unicode без кодирования (v2rayN пишет имена как есть).
func TestSweepFragmentUnicodeSpaces(t *testing.T) {
	link := "vless://" + swUUID + "@example.com:443?security=tls&type=tcp#My Server 🇩🇪 №1"
	outs, err := swParseAll(t, link)
	if err != nil || len(outs) != 1 {
		t.Fatalf("unicode fragment must parse, got outs=%d err=%v", len(outs), err)
	}
	if !strings.Contains(outs[0].Tag, "My Server 🇩🇪 №1") {
		t.Errorf("fragment lost/mangled in tag: %q", outs[0].Tag)
	}
}

// Пустой query "?" перед фрагментом.
func TestSweepEmptyQuery(t *testing.T) {
	link := "trojan://password123@example.com:443?#eq"
	outs, err := swParseAll(t, link)
	if err != nil || len(outs) != 1 {
		t.Errorf("empty '?' query must parse, got outs=%d err=%v", len(outs), err)
	}
}

// ---------------------------------------------------------------------------
// 5. Дефолт порта по схеме. vless/trojan/ss/hy2 → 443 (совпадает с v2rayN),
// ssh → 22. socks/http идут с default 0 (socks.go:30, http.go:9) — узел
// «парсится» в server_port=0 и умирает на старте, а прокси-листы сплошь и рядом
// без порта не ходят, но curl-конвенция socks5://host (порт 1080) и
// http://host (порт 80) существуют.
// ---------------------------------------------------------------------------

func TestSweepMissingPortTrojanDefaults443(t *testing.T) {
	outs, err := swParseAll(t, swTrojanNoPort("np"))
	if err != nil || len(outs) != 1 {
		t.Fatalf("portless trojan must parse, got outs=%d err=%v", len(outs), err)
	}
	to := outs[0].Options.(*option.TrojanOutboundOptions)
	if to.ServerPort != 443 {
		t.Errorf("portless trojan must default 443, got %d", to.ServerPort)
	}
}

func TestSweepMissingPortSocksHTTP(t *testing.T) {
	outs, err := swParseAll(t, "socks5://user:pass@10.0.0.1#s")
	if err != nil || len(outs) != 1 {
		t.Fatalf("portless socks5 must parse, got outs=%d err=%v", len(outs), err)
	}
	so := outs[0].Options.(*option.SOCKSOutboundOptions)
	if so.ServerPort == 0 {
		t.Errorf("portless socks5 yields server_port=0 (dead node); curl convention defaults 1080")
	}

	outs2, err := swParseAll(t, "http://user:pass@10.0.0.2#h")
	if err != nil || len(outs2) != 1 {
		t.Fatalf("portless http must parse, got outs=%d err=%v", len(outs2), err)
	}
	ho := outs2[0].Options.(*option.HTTPOutboundOptions)
	if ho.ServerPort == 0 {
		t.Errorf("portless http yields server_port=0 (dead node); should default 80")
	}
}

// ---------------------------------------------------------------------------
// 6. Разделители внутри строки / мусор перед схемой.
// ---------------------------------------------------------------------------

// Лидирующие пробелы перед схемой (копипаста из чата/маркдауна с отступом):
// (?m)^prefix не матчит " vless://" → строка-одиночка не распознаётся, в списке
// клеится к предыдущей ноде.
func TestSweepLeadingWhitespaceBeforeScheme(t *testing.T) {
	outs, err := swParseAll(t, "  "+swVless("indent"))
	if err != nil || len(outs) != 1 {
		t.Errorf("indented single link must parse, got outs=%d err=%v", len(outs), err)
	}

	body := swVless("a") + "\n\t" + swVless("b")
	outs2, err := swParseAll(t, body)
	if err != nil {
		t.Fatalf("indented list must parse: %v", err)
	}
	if len(outs2) != 2 {
		t.Errorf("expected 2 outbounds (indented line lost/merged), got %d", len(outs2))
	}
}

// Табы между ссылками на одной строке (копипаста из Excel/Sheets).
func TestSweepTabSeparatedLinks(t *testing.T) {
	body := swVless("a") + "\t" + swVless("b")
	outs, err := swParseAll(t, body)
	if err != nil {
		t.Fatalf("tab-separated pair must parse: %v", err)
	}
	if len(outs) != 2 {
		t.Errorf("expected 2 outbounds from tab-separated line, got %d", len(outs))
	}
}
