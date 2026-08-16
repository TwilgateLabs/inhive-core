// commands_liveness_test.go — resolveRealOutboundTag (audit A2, 2026-08-11):
// разворот селектора/вложенных групп до тега реального сервера, по которому
// circuit-breaker ключует здоровье. Без разворота SystemInfo.current_outbound_down
// сравнивал бы теги из разных пространств и не загорелся бы никогда — ровно
// класс бага, который ловил TestExchangeCircuitOpenUnwrapsSelector в dns.
package hcore

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// stubOutbound — минимальный adapter.Outbound.
type stubOutbound struct {
	tag string
}

func (s *stubOutbound) Type() string           { return "stub" }
func (s *stubOutbound) Tag() string            { return s.tag }
func (s *stubOutbound) Network() []string      { return []string{N.NetworkTCP} }
func (s *stubOutbound) Dependencies() []string { return nil }
func (s *stubOutbound) DisplayType() string    { return "stub" }
func (s *stubOutbound) IsReady() bool          { return true }
func (s *stubOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, nil
}
func (s *stubOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, nil
}

// stubGroup — adapter.OutboundGroup поверх stubOutbound.
type stubGroup struct {
	stubOutbound
	now string
}

func (s *stubGroup) Now() string   { return s.now }
func (s *stubGroup) All() []string { return nil }

// stubLookup — outboundLookup по map.
type stubLookup map[string]adapter.Outbound

func (s stubLookup) Outbound(tag string) (adapter.Outbound, bool) {
	o, ok := s[tag]
	return o, ok
}

func TestResolveRealOutboundTag_UnwrapsSelector(t *testing.T) {
	om := stubLookup{
		"select": &stubGroup{stubOutbound: stubOutbound{tag: "select"}, now: "srv-nl"},
		"srv-nl": &stubOutbound{tag: "srv-nl"},
	}
	if got := resolveRealOutboundTag(om, "select"); got != "srv-nl" {
		t.Fatalf("ожидал srv-nl, получил %q", got)
	}
}

func TestResolveRealOutboundTag_NestedGroups(t *testing.T) {
	// селектор → urltest-группа → реальный сервер
	om := stubLookup{
		"select": &stubGroup{stubOutbound: stubOutbound{tag: "select"}, now: "auto"},
		"auto":   &stubGroup{stubOutbound: stubOutbound{tag: "auto"}, now: "srv-de"},
		"srv-de": &stubOutbound{tag: "srv-de"},
	}
	if got := resolveRealOutboundTag(om, "select"); got != "srv-de" {
		t.Fatalf("ожидал srv-de, получил %q", got)
	}
}

func TestResolveRealOutboundTag_MissingTag(t *testing.T) {
	// Чужой конфиг без нашего селектора (universal client) → "" (не врём).
	om := stubLookup{}
	if got := resolveRealOutboundTag(om, "select"); got != "" {
		t.Fatalf("ожидал пустую строку, получил %q", got)
	}
}

func TestResolveRealOutboundTag_EmptyGroup(t *testing.T) {
	// Now()=="" (пустой селектор) → возвращаем тег группы; брейкер по нему
	// health не ведёт → down=false, индикатор молчит (честное «неизвестно»).
	om := stubLookup{
		"select": &stubGroup{stubOutbound: stubOutbound{tag: "select"}, now: ""},
	}
	if got := resolveRealOutboundTag(om, "select"); got != "select" {
		t.Fatalf("ожидал select, получил %q", got)
	}
}

func TestResolveRealOutboundTag_GroupCycle(t *testing.T) {
	// Цикл групп в кривом конфиге не должен зависать — потолок итераций.
	om := stubLookup{
		"a": &stubGroup{stubOutbound: stubOutbound{tag: "a"}, now: "b"},
		"b": &stubGroup{stubOutbound: stubOutbound{tag: "b"}, now: "a"},
	}
	got := resolveRealOutboundTag(om, "a")
	if got != "a" && got != "b" {
		t.Fatalf("ожидал a|b (обрыв по потолку), получил %q", got)
	}
}

func TestResolveRealOutboundTag_DanglingNow(t *testing.T) {
	// Now() указывает на отсутствующий тег → возвращаем последний найденный.
	om := stubLookup{
		"select": &stubGroup{stubOutbound: stubOutbound{tag: "select"}, now: "ghost"},
	}
	if got := resolveRealOutboundTag(om, "select"); got != "ghost" {
		t.Fatalf("ожидал ghost, получил %q", got)
	}
}
