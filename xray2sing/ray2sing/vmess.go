package ray2sing

import (
	"fmt"
	"strconv"

	T "github.com/sagernet/sing-box/option"

	"encoding/json"
)

func decodeVmess(vmessConfig string) (map[string]string, error) {
	vmessData := vmessConfig[8:]
	decodedData, err := decodeBase64FaultTolerant(vmessData)
	if err != nil {
		return nil, err
	}
	var data map[string]interface{}
	err = json.Unmarshal([]byte(decodedData), &data)
	if err != nil {
		return nil, err
	}
	strdata := convertToStrings(data)
	return strdata, nil
}

func convertToStrings(data map[string]interface{}) map[string]string {
	stringMap := make(map[string]string)
	for key, value := range data {
		switch v := value.(type) {
		case string:
			stringMap[key] = v
		case float64:
			stringMap[key] = strconv.Itoa(int(v))
		// case map[string]interface{}:
		// 	stringMap[key] = convertToStrings(v)

		default:
			stringMap[key] = fmt.Sprintf("%v", v)
		}
	}
	return stringMap

}

func VmessSingbox(vmessURL string) (*T.Outbound, error) {
	decoded, err := decodeVmess(vmessURL)
	if err != nil {
		return nil, err
	}

	port := toUInt16(decoded["port"], 443)
	transportOptions, err := getTransportOptions(decoded)
	if err != nil {
		return nil, err
	}
	security := "auto"
	if decoded["scy"] != "" {
		security = decoded["scy"]
	}
	// Leave PacketEncoding empty (upstream/runtime default = disabled) unless the
	// subscription carries an explicit hint. Forcing xudp on a server without XUDP
	// support can silently mishandle UDP-associated traffic.
	packetEncoding := decoded["packetEncoding"]
	// vmess base64 JSON carries no fingerprint field; default to chrome so the
	// TLS ClientHello isn't the trivially-detectable Go-default stack (DPI).
	if decoded["tls"] == "tls" && decoded["fp"] == "" {
		decoded["fp"] = "chrome"
	}
	return &T.Outbound{
		Tag:  decoded["ps"],
		Type: "vmess",
		Options: &T.VMessOutboundOptions{
			DialerOptions: getDialerOptions(decoded),
			ServerOptions: T.ServerOptions{
				Server:     decoded["add"],
				ServerPort: port,
			},
			UUID:          decoded["id"],
			Security:      security,
			AlterId:       toInt(decoded["aid"]),
			GlobalPadding: false,
			// Default false (upstream parity); no standard vmess base64 field
			// signals it, and runtime negotiates the bit on the wire. Only set
			// true on an explicit hint to stay safe on legacy non-TLS AEAD nodes.
			AuthenticatedLength:         decoded["authenticatedLength"] == "true",
			PacketEncoding:              packetEncoding,
			OutboundTLSOptionsContainer: getTLSOptions(decoded),
			Transport:                   transportOptions,
			Multiplex:                   getMuxOptions(decoded),
		},
	}, nil
}
