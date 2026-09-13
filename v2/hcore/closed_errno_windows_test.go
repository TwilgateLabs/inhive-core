//go:build windows

// Только Windows: winsock сообщает RST/abort/not-connected своими кодами
// (WSAECONNRESET=10054, WSAECONNABORTED=10053, WSAENOTCONN=10057), а
// syscall.ECONNRESET на этой ОС — фиктивная константа (APPLICATION_ERROR+n),
// и Errno.Is их не сопоставляет. Поэтому фильтр «тихого закрытия» в sing
// обязан знать WSA-коды отдельно. На Unix-платформах такой проблемы нет —
// там errno один и тот же.
//
// Что защищает тест: без этого каждое закрытие соединения локальным
// приложением (RST от торрент-клиента, браузера, чего угодно) sing-box и все
// sing-* модули логируют как ERROR. 2026-09-13: ~4 ERROR/с в трёх стоках
// (box.log, core.log, gRPC LogListener) и 16–25% CPU у InHive.exe.
package hcore

import (
	"net"
	"os"
	"syscall"
	"testing"

	E "github.com/sagernet/sing/common/exceptions"
)

func TestIsClosed_WinsockErrnos(t *testing.T) {
	cases := map[string]syscall.Errno{
		"WSAECONNABORTED": syscall.Errno(10053),
		"WSAECONNRESET":   syscall.Errno(10054),
		"WSAENOTCONN":     syscall.Errno(10057),
	}
	for name, code := range cases {
		// Ровно та обёртка, которую отдаёт net на Windows: OpError → SyscallError → Errno.
		err := &net.OpError{Op: "read", Net: "tcp", Err: &os.SyscallError{Syscall: "wsarecv", Err: code}}
		if !E.IsClosed(err) {
			t.Errorf("%s (%d): IsClosed=false — такое закрытие уйдёт в лог как ERROR", name, code)
		}
		if !E.IsClosedOrCanceled(err) {
			t.Errorf("%s (%d): IsClosedOrCanceled=false", name, code)
		}
	}
}
