// pause.go — pause/wake/close operations for mobile background handling.
package hcore

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/service"
	hcommon "github.com/twilgate/inhive-core/v2/hcommon"
)

// wakeResetMinPause — минимальная длительность сна девайса, после которой Wake()
// принудительно сбрасывает сетевое состояние ядра (см. maybeResetAfterLongSleep).
//
// Почему именно 30 секунд:
//   - после ≥30с заморозки процесса живых in-flight соединений практически нет
//     (NE не получал CPU — туннелем никто не пользовался);
//   - UDP/NAT-мэппинги у операторов и домашних роутеров начинают истекать на
//     30-60с простоя — «тот же» сокет после такой паузы уже смотрит в никуда;
//   - hysteria2 QUIC MaxIdleTimeout = 30s (sing-quic hysteria/protocol.go) — на
//     этой границе QUIC-сессия мертва уже по определению протокола.
//
// Ниже порога (короткий сон: экран погас на минуту) НИЧЕГО не рвём — iOS зовёт
// sleep()/wake() часто (Apple: «called with high frequency»), и безусловный
// сброс на каждый wake рвал бы живые загрузки.
const wakeResetMinPause = 30 * time.Second

func (s *CoreService) Close(ctx context.Context, closeReq *CloseRequest) (resp *hcommon.Empty, err error) {
	if closeReq == nil {
		return nil, nil
	}
	mode := closeReq.Mode
	if grpcServer[mode] == nil {
		Log(LogLevel_WARNING, LogType_CORE, "grpcServer already stoped")
		return nil, nil
	}

	CloseGrpcServer(mode)
	return &hcommon.Empty{}, nil
}

func Pause() {
	if box := static.Instance(); box != nil {
		if manager := box.PauseManager(); manager != nil {
			manager.DevicePause()
			// Метка для wake-reset-гейта. Пишем на любой мобильной платформе,
			// зовущей mobile.Pause/Wake (iOS NE sleep/wake); Windows-сон идёт
			// другим путём (notifyWindowsPowerEvent) и делает ResetNetwork сам.
			static.pausedAtNano.Store(time.Now().UnixNano())
			if C.IsIos {
				// iOS: авто-DeviceWake через минуту, чтобы фоновый push-трафик
				// ночью не жил под вечной паузой (апстримный паттерн libbox
				// CommandServer.Pause).
				//
				// ВСЕГДА пересоздаём таймер, НЕ Reset() старого: AfterFunc
				// замыкает manager КОНКРЕТНОГО box'а, а pause.Manager у нас
				// per-box (box.go: pause.WithDefaultManager на каждый Start,
				// libbox.BaseContext менеджера в ctx не кладёт). Прежний
				// `Reset()` после любого рестарта ядра внутри живого
				// NE-процесса (смена подписки, hot-add-fallback-пересборка)
				// будил manager уже ЗАКРЫТОГО box'а — актуальный box оставался
				// DevicePaused до следующего явного wake(), т.е. потенциально
				// всю ночь: замороженные WireGuard-таймеры (wireguard-go
				// timers.go WaitActive) и все pause.RegisterTicker-циклы.
				static.pauseMu.Lock()
				if static.endPauseTimer != nil {
					static.endPauseTimer.Stop()
				}
				static.endPauseTimer = time.AfterFunc(time.Minute, manager.DeviceWake)
				static.pauseMu.Unlock()
			}
		}
	}
}

// resetPauseState чистит хвосты паузы при остановке бокса (Stop/StopAndAlert):
//   - pausedAtNano: иначе рестарт ядра между Pause() и Wake() (смена подписки
//     во время сна) приписал бы «чужой» сон свежему боксу, и первый же Wake()
//     сделал бы ему ненужный wake-reset (на iOS практически недостижимо — оба
//     процесса заморожены — но висяк дешевле почистить, чем объяснять);
//   - endPauseTimer: его замыкание держит pause.Manager ОСТАНОВЛЕННОГО бокса —
//     выстрел после рестарта был бы no-op'ом по чужому manager'у, а Pause()
//     нового цикла всё равно создаёт таймер заново.
func resetPauseState() {
	static.pausedAtNano.Store(0)
	static.pauseMu.Lock()
	if static.endPauseTimer != nil {
		static.endPauseTimer.Stop()
		static.endPauseTimer = nil
	}
	static.pauseMu.Unlock()
}

func Wake() {
	if box := static.Instance(); box != nil {
		if manager := box.PauseManager(); manager != nil {
			// if !C.IsIos {
			manager.DeviceWake()
			// }
		}
	}
	maybeResetAfterLongSleep()
}

// maybeResetAfterLongSleep — принудительный сброс протухшего сетевого состояния
// после долгого сна девайса. Закрывает главный пробел iOS-пути: Windows-resume
// делает ResetNetwork (route/network.go notifyWindowsPowerEvent), а wake() на
// iOS не делал НИЧЕГО — same-interface путь дедупится монитором
// (libbox/monitor.go same-iface early-return), и все протухшие за сон сессии
// (gRPC/xhttp-транспорт к серверу, DoH H2 к DNS-провайдеру, QUIC) жили до своих
// аварийных таймаутов: «первые 10-20 секунд после пробуждения VPN не работает»
// (device-лог 2026-07-25).
//
// Что сбрасываем и почему ровно это:
//   - NetworkManager.ResetNetwork() — CloseAll всех проксируемых соединений +
//     InterfaceUpdated() у outbounds/endpoints/inbounds (vless рвёт transport,
//     hysteria2/tuic закрывают QUIC, WG ре-биндится) — ровно то, что делает
//     Windows-resume;
//   - Reset() всех DNS-транспортов — мёртвые DoH H2-коннекты выбрасываются, не
//     дожидаясь C.DNSTimeout на первом юзерском запросе.
//
// Чего НЕ делаем (осознанно, не забыто — чтобы следующий не «дочинил»):
//   - НЕ полный Router().ResetNetwork(): тот дополнительно зовёт
//     dns.Router.ResetNetwork → ClearCache → platformInterface.ClearDNSCache,
//     что на iOS = Swift clearDNSCache = setTunnelNetworkSettings(nil→settings),
//     т.е. re-assert туннеля: секунды простоя и флап reasserting — противоречит
//     цели ускорить пробуждение и блокирует вызывающий поток;
//   - НЕ чистим DNS-кэш ядра: записи с живым TTL после сна валидны (интерфейс
//     тот же), а холодный кэш = каждый домен заново через DoH — замедление
//     ровно в тот момент, когда всё и так медленно.
//
// Сброс уходит в горутину: wake() приходит с NE-очереди и обязан возвращаться
// быстро, а CloseAll берёт локи и может касаться сотен соединений.
func maybeResetAfterLongSleep() {
	pausedNano := static.pausedAtNano.Swap(0)
	if pausedNano == 0 {
		return
	}
	elapsed := time.Since(time.Unix(0, pausedNano))
	if elapsed < wakeResetMinPause {
		return
	}
	box := static.Box()
	if box == nil {
		return
	}
	boxCtx := static.Context()
	Log(LogLevel_INFO, LogType_CORE, fmt.Sprintf(
		"wake: slept %s (>=%s) — resetting stale network state",
		elapsed.Round(time.Second), wakeResetMinPause))
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Гонка wake vs параллельный Stop (box закрывается под нами) —
				// сброс тогда и не нужен. Логируем, не роняем процесс.
				Log(LogLevel_ERROR, LogType_CORE, fmt.Sprintf(
					"wake-reset panic (box closing?): %v\n%s", r, string(debug.Stack())))
			}
		}()
		box.Network().ResetNetwork()
		if boxCtx != nil {
			if tm := service.FromContext[adapter.DNSTransportManager](boxCtx); tm != nil {
				for _, transport := range tm.Transports() {
					transport.Reset()
				}
			}
		}
	}()
}
