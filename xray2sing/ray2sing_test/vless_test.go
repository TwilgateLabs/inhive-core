package ray2sing_test

import (
	"testing"

	"github.com/twilgate/xray2sing/ray2sing"
)

func TestVless(t *testing.T) {

	url := "vless://25da296e-1d96-48ae-9867-4342796cd742@172.67.149.95:443?encryption=none&fp=chrome&host=vless.229feb8b52a0e7e117ea76f8b591bcb3.workers.dev&path=%2F%3Fed%3D2048&security=tls&sni=vless.229feb8b52a0e7e117ea76f8b591bcb3.workers.dev&type=ws#رایگان | VLESS | @Helix_Servers | US🇺🇸 | 0️⃣1️⃣"

	// Define the expected JSON structure
	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "vless",
			"tag": "رایگان | VLESS | @Helix_Servers | US🇺🇸 | 0️⃣1️⃣ § 0",
			"server": "172.67.149.95",
			"server_port": 443,
			"uuid": "25da296e-1d96-48ae-9867-4342796cd742",
			"tls": {
			  "enabled": true,
			  "server_name": "vless.229feb8b52a0e7e117ea76f8b591bcb3.workers.dev",
			  "alpn": "http/1.1",
			  "utls": {
				"enabled": true,
				"fingerprint": "chrome"
			  }
			},
			"transport": {
			  "type": "ws",
			  "path": "/",
			  "headers": {
				"Host": "vless.229feb8b52a0e7e117ea76f8b591bcb3.workers.dev"
			  },
			  "max_early_data": 2048,
			  "early_data_header_name": "Sec-WebSocket-Protocol"
			},
			"packet_encoding": "xudp"
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}

// Xray/v2rayN share links use packetEncoding=none for "disabled"; sing-box only
// knows ""/packetaddr/xudp and rejects (used to panic on) anything else. The
// converter must translate, not pass through (seen live: vlessforu sub, 2026-08-24).
func TestVlessPacketEncodingNone(t *testing.T) {
	url := "vless://25da296e-1d96-48ae-9867-4342796cd742@172.67.149.95:443?encryption=none&security=tls&sni=example.com&type=tcp&packetEncoding=none#pe-none"

	expectedJSON := `
	{
		"outbounds": [
		  {
			"type": "vless",
			"tag": "pe-none § 0",
			"server": "172.67.149.95",
			"server_port": 443,
			"uuid": "25da296e-1d96-48ae-9867-4342796cd742",
			"tls": {
			  "enabled": true,
			  "server_name": "example.com"
			},
			"packet_encoding": ""
		  }
		]
	  }
	`
	ray2sing.CheckUrlAndJson(url, expectedJSON, t)
}
