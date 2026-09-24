package mobile

import (
	"context"
	"testing"

	hcore "github.com/twilgate/inhive-core/v2/hcore"
)

// Аудит 2026-09-25, топ №1: standalone-ядро VPN-off (Android StandaloneCore,
// iOS MainAppCore) стартовало через Start → StartRequest без признака
// ping-only → ядро сохраняло lite-конфиг без inbounds как last-start →
// headless-реплей плитки поднимал его вместо туннеля. Признак ping-only
// принадлежит намерению вызывающего и обязан дойти до ядра по gomobile-пути
// так же, как по gRPC (StartRequest.ping_only). Что ядро по этому признаку
// не пишет last-start — hcore/start_ping_only_test.go.
func TestMobileStartEntriesCarryPingOnlyIntent(t *testing.T) {
	var got []*hcore.StartRequest
	prev := startService
	startService = func(_ context.Context, in *hcore.StartRequest) (*hcore.CoreInfoResponse, error) {
		got = append(got, in)
		return &hcore.CoreInfoResponse{}, nil
	}
	t.Cleanup(func() { startService = prev })

	if err := StartPingOnly("ping-cfg"); err != nil {
		t.Fatal(err)
	}
	if err := Start("", "connect-cfg"); err != nil {
		t.Fatal(err)
	}
	if err := Start("", ""); err != nil { // headless-реплей плитки
		t.Fatal(err)
	}

	want := []struct {
		content  string
		pingOnly bool
	}{{"ping-cfg", true}, {"connect-cfg", false}, {"", false}}
	if len(got) != len(want) {
		t.Fatalf("calls = %d, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].ConfigContent != w.content || got[i].PingOnly != w.pingOnly {
			t.Errorf("call %d: content=%q pingOnly=%v, want %q/%v",
				i, got[i].ConfigContent, got[i].PingOnly, w.content, w.pingOnly)
		}
		if !got[i].EnableRawConfig {
			t.Errorf("call %d: EnableRawConfig=false (legacy translator)", i)
		}
	}
}
