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

// wakeProbeMinFrozen — минимальная длительность ЗАМОРОЗКИ процесса (не паузы
// по sleep/wake!), после которой Wake() проверяет пулы долгоживущих соединений.
//
// История (чтобы следующий не «дочинил» обратно):
//   - 2026-07-26: после реального ночного сна протухшие сессии (DoH h2, xhttp
//     h2-пул, QUIC) жили до аварийных таймаутов — «первые 10–20 с после
//     пробуждения VPN не работает». Поставили ResetNetwork на wake при паузе
//     ≥30 с по образцу Windows-resume.
//   - 2026-09-07 (device-дамп, 79 циклов sleep/wake за 41 мин): iOS зовёт
//     sleep() на блокировку экрана и wake() на разблокировку/подсветку от
//     уведомления каждые 20–50 с. Гейт «≥30 с» срабатывал в 33 из 34 случаев по
//     ЖИВЫМ соединениям (открыты в предыдущем wake-бёрсте, используются прямо
//     сейчас) — видео в Telegram на iPhone не догружалось никогда, на Windows на
//     том же сервере — мгновенно. Посылка «≥30 с паузы = процесс был заморожен»
//     ложна: sleep() ≠ фриз.
//   - Go на darwin/iOS берёт nanotime из mach_absolute_time, которое НЕ идёт,
//     пока SoC спит (golang/go#35012, #66870; WireGuard-apple и Proton возят
//     патч рантайма на mach_continuous_time). Значит разница «wall-часы минус
//     monotonic» за паузу — это и есть время, которое процесс не работал.
//     Именно её и меряем (frozenSince), а не длину паузы.
//
// Порог 2 мин — по апстриму sing-box 1.15 (a8849d22f6, «Keep idle connections
// across short device sleeps»: по их power-report'ам «most sleeps last under
// two minutes and none exceeded ten»). Короче — начнём пинговать на каждый
// wake (iOS 17: раз в ~6 с), радио не уснёт (Tailscale #1554 получил на этом
// регресс батареи). Длиннее — теряем смысл: после 10 мин NAT-мэппинги мертвы.
const wakeProbeMinFrozen = 2 * time.Minute

// wakeProbeBudget — общий дедлайн одной пробы (все outbound'ы + DNS). Больше
// одного PingTimeout (15 с) с запасом на последовательный обход outbound'ов.
const wakeProbeBudget = 45 * time.Second

// wakeLogMinFrozen — с какой заморозки писать строку в box.log даже без пробы:
// нужна статистика реального распределения снов на устройствах (у апстрима она
// есть — power report, у нас нет), а на каждый 20-секундный wake писать нельзя
// (уровень WARN — единственный, что доезжает до вкладки «Логи»).
const wakeLogMinFrozen = 30 * time.Second

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
			static.pauseMu.Lock()
			// Метка для гейта пробы после сна (см. frozenSince). Пишем на любой
			// мобильной платформе, зовущей mobile.Pause/Wake (iOS NE sleep/wake);
			// Windows-сон идёт другим путём (notifyWindowsPowerEvent) и делает
			// ResetNetwork сам — там событие = реальный suspend.
			static.pausedAt = time.Now()
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
				//
				// Таймер идёт по monotonic, т.е. считает только время
				// бодрствования и внутри реального сна не истекает — это
				// желаемое поведение (апстрим полагается на то же).
				if static.endPauseTimer != nil {
					static.endPauseTimer.Stop()
				}
				static.endPauseTimer = time.AfterFunc(time.Minute, manager.DeviceWake)
			}
			static.pauseMu.Unlock()
		}
	}
}

// resetPauseState чистит хвосты паузы при остановке бокса (Stop/StopAndAlert):
//   - pausedAt: иначе рестарт ядра между Pause() и Wake() (смена подписки во
//     время сна) приписал бы «чужой» сон свежему боксу;
//   - endPauseTimer: его замыкание держит pause.Manager ОСТАНОВЛЕННОГО бокса —
//     выстрел после рестарта был бы no-op'ом по чужому manager'у, а Pause()
//     нового цикла всё равно создаёт таймер заново.
func resetPauseState() {
	static.pauseMu.Lock()
	static.pausedAt = time.Time{}
	if static.endPauseTimer != nil {
		static.endPauseTimer.Stop()
		static.endPauseTimer = nil
	}
	static.pauseMu.Unlock()
}

func Wake() {
	if box := static.Instance(); box != nil {
		if manager := box.PauseManager(); manager != nil {
			// На каждый wake, включая iOS. Апстрим на iOS wake игнорирует и ждёт
			// минутный таймер — который по monotonic считает только бодрствование:
			// sing-box#4509 (2026-09-07) — 50 с простоя WireGuard после
			// разблокировки ровно из-за этого. Не копировать.
			manager.DeviceWake()
		}
	}
	maybeProbeAfterFrozenSleep()
}

// frozenSince — сколько wall-времени прошло с паузы и сколько из него процесс
// НЕ работал. wall — по стенным часам (Round(0) стирает monotonic-компоненту),
// awake — по monotonic, которое на darwin стоит во сне SoC. frozen = wall −
// awake, клампится к нулю (часы могли подвести назад). Чистая функция — под
// тест: свойство «пауза без заморозки никогда не ведёт к пробе» проверяется
// без box'а.
func frozenSince(pausedAt, now time.Time) (wall, frozen time.Duration) {
	return frozenSinceParts(pausedAt, now, now)
}

// frozenSinceParts — та же математика с раздельными показаниями «сейчас» по
// wall и по monotonic (одно значение time.Time с расходящимися шкалами собрать
// нельзя — нужно тестам, чтобы имитировать сон SoC).
func frozenSinceParts(pausedAt, nowWall, nowMono time.Time) (wall, frozen time.Duration) {
	wall = nowWall.Round(0).Sub(pausedAt.Round(0))
	awake := nowMono.Sub(pausedAt)
	frozen = wall - awake
	if frozen < 0 {
		frozen = 0
	}
	if wall < 0 {
		wall = 0
	}
	return wall, frozen
}

// shouldProbeAfterSleep — решение гейта. Только по заморозке: длинная пауза с
// работавшим ядром (телефон на столе, wake-бёрсты по уведомлениям) — это
// ситуация, где keepalive'ы транспортов делали свою работу, а живые стримы
// трогать нельзя.
func shouldProbeAfterSleep(frozen time.Duration) bool {
	return frozen >= wakeProbeMinFrozen
}

// maybeProbeAfterFrozenSleep — ПРОВЕРКА (не сброс) долгоживущих соединений
// после реальной заморозки процесса. Принцип: время — не улика, улика — ответ
// сети; время лишь решает, КОГДА спросить.
//
// Что делаем:
//   - outbound'ы с adapter.SleepProber (vless/vmess/trojan поверх xhttp): PING по
//     каждому h2-соединению xmux-пулов, закрываются ТОЛЬКО не ответившие за
//     штатный PingTimeout (15 с); живые стримы не трогаются;
//   - DNS-транспорты: Reset() — у DoH это CloseIdleConnections + Clone, т.е.
//     закрывает только соединения без стримов (между запросами их и нет);
//     in-flight запрос не пострадает;
//   - hysteria2/tuic (QUIC): ничего — у QUIC свой keepalive и MaxIdleTimeout,
//     после заморозки просроченный таймер закроет сессию сам.
//
// Чего НЕ делаем (осознанно):
//   - НЕ Network().ResetNetwork(): CloseAll всех проксируемых conn +
//     InterfaceUpdated → XmuxManager.Reset() рвёт занятые соединения. Это и был
//     баг 2026-09-07. ResetNetwork остаётся для РЕАЛЬНОЙ смены интерфейса
//     (route/network.go notifyInterfaceUpdate) и Windows-resume — не трогать.
//   - НЕ Router().ResetNetwork(): дополнительно чистит DNS-кэш через
//     platformInterface.ClearDNSCache → на iOS re-assert туннеля (секунды
//     простоя, флап reasserting).
//
// Проба уходит в горутину: wake() приходит с NE-очереди и обязан возвращаться
// быстро, а PING'и ждут до 15 с.
func maybeProbeAfterFrozenSleep() {
	static.pauseMu.Lock()
	pausedAt := static.pausedAt
	static.pausedAt = time.Time{}
	static.pauseMu.Unlock()
	if pausedAt.IsZero() {
		return
	}
	wall, frozen := frozenSince(pausedAt, time.Now())
	if !shouldProbeAfterSleep(frozen) {
		if frozen >= wakeLogMinFrozen {
			Log(LogLevel_WARNING, LogType_CORE, fmt.Sprintf(
				"wake: paused %s, frozen %s (<%s) — keeping connections",
				wall.Round(time.Second), frozen.Round(time.Second), wakeProbeMinFrozen))
		}
		return
	}
	box := static.Box()
	if box == nil {
		return
	}
	boxCtx := static.Context()
	Log(LogLevel_WARNING, LogType_CORE, fmt.Sprintf(
		"wake: paused %s, frozen %s (>=%s) — probing pooled connections",
		wall.Round(time.Second), frozen.Round(time.Second), wakeProbeMinFrozen))
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Гонка wake vs параллельный Stop (box закрывается под нами) —
				// проба тогда и не нужна. Логируем, не роняем процесс.
				Log(LogLevel_ERROR, LogType_CORE, fmt.Sprintf(
					"wake-probe panic (box closing?): %v\n%s", r, string(debug.Stack())))
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), wakeProbeBudget)
		defer cancel()
		startedAt := time.Now()
		var probed, closed, outbounds int
		for _, outbound := range box.Outbound().Outbounds() {
			prober, ok := outbound.(adapter.SleepProber)
			if !ok {
				continue
			}
			p, c := prober.ProbeAfterSleep(ctx)
			if p > 0 {
				outbounds++
			}
			probed += p
			closed += c
		}
		var dnsReset int
		if boxCtx != nil {
			if tm := service.FromContext[adapter.DNSTransportManager](boxCtx); tm != nil {
				for _, transport := range tm.Transports() {
					transport.Reset()
					dnsReset++
				}
			}
		}
		Log(LogLevel_WARNING, LogType_CORE, fmt.Sprintf(
			"wake-probe: %d h2 conns on %d outbounds pinged, %d dead closed, %d dns transports idle-reset, %s",
			probed, outbounds, closed, dnsReset, time.Since(startedAt).Round(time.Millisecond)))
	}()
}
