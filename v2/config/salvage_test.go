package config

// Тесты фикса fatal-аудита 2026-08-25: сохранённый профиль с одной невалидной
// записью (тип, удалённый ядром; строгое поле) реплеился на каждом старте и
// убивал ВСЕ сервера до create-фазы. Теперь невалидные записи выбрасываются
// per-entry (salvage), ноль выживших — честная ошибка.

import (
	"testing"

	"github.com/sagernet/sing-box/experimental/libbox"
)

const goodVless = `{"type":"vless","tag":"good","server":"1.2.3.4","server_port":443,"uuid":"11111111-2222-3333-4444-555555555555","tls":{"enabled":true,"server_name":"example.com"}}`

func TestSalvageDropsUnknownOutboundType(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	content := `{"outbounds":[{"type":"hysteria3","tag":"bad"},` + goodVless + `]}`
	opts, err := ReadSingOptions(ctx, &ReadOptions{Content: content})
	if err != nil {
		t.Fatalf("profile with one unknown-type outbound must salvage, got: %v", err)
	}
	if len(opts.Outbounds) != 1 || opts.Outbounds[0].Tag != "good" {
		t.Fatalf("expected only the good outbound to survive, got %d", len(opts.Outbounds))
	}
}

func TestSalvageDropsDeprecatedDNSOutbound(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	content := `{"outbounds":[{"type":"dns","tag":"dns-out"},` + goodVless + `]}`
	opts, err := ReadSingOptions(ctx, &ReadOptions{Content: content})
	if err != nil {
		t.Fatalf("profile with legacy dns outbound must salvage, got: %v", err)
	}
	if len(opts.Outbounds) != 1 {
		t.Fatalf("expected 1 survivor, got %d", len(opts.Outbounds))
	}
}

func TestSalvageZeroSurvivorsIsHonestError(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	content := `{"outbounds":[{"type":"hysteria3","tag":"bad1"},{"type":"nope","tag":"bad2"}]}`
	if _, err := ReadSingOptions(ctx, &ReadOptions{Content: content}); err == nil {
		t.Fatalf("profile where nothing survives must fail, not silently start empty")
	}
}

// Групповой линт box.New (sing-box/box.go): висячий member/default в
// selector раньше проходил CheckConfigOptions и убивал профиль на Start.
func TestGroupDanglingMemberLinted(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	content := `{"outbounds":[{"type":"selector","tag":"pick","outbounds":["typo-tag","good"],"default":"typo-tag"},` + goodVless + `]}`
	opts, err := ReadSingOptions(ctx, &ReadOptions{Content: content})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := libbox.CheckConfigOptions(opts); err != nil {
		t.Fatalf("selector with a dangling member must pass (member dropped with warn), got: %v", err)
	}
}

func TestGroupAllMembersDanglingRejected(t *testing.T) {
	ctx := libbox.BaseContext(nil)
	content := `{"outbounds":[{"type":"selector","tag":"pick","outbounds":["typo-tag"]},` + goodVless + `]}`
	opts, err := ReadSingOptions(ctx, &ReadOptions{Content: content})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := libbox.CheckConfigOptions(opts); err == nil {
		t.Fatalf("group with zero valid members must be rejected at import time")
	}
}
