// proxy_info.go — outbound tag display helper.
//
// The OutboundsInfo / MainOutboundsInfo streams (GetAllProxiesInfo,
// AllProxiesInfoStream, GetProxyInfo) were removed on 2026-09-23 together with
// the core CLI, their only caller. The OutboundGroup / OutboundInfo messages stay
// in hcore.proto: ../app/lib/core/bridge.dart still re-exports them.
package hcore

import "strings"

func TrimTagName(tag string) string {
	return strings.Trim(strings.Split(tag, "§")[0], " ")
}
