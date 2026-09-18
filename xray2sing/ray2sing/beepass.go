package ray2sing

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	T "github.com/sagernet/sing-box/option"
)

type beepassData struct {
	Server string `json:"server"`
	// json.Number: the Outline/BeePass dynamic-access-key spec returns
	// server_port as a NUMBER ({"server_port":443}); some providers quote it as
	// a string. json.Number unmarshals from either token, where a plain string
	// field failed on the numeric (spec-conformant) form and silently dropped
	// the node via the ss://-body fallback.
	ServerPort json.Number `json:"server_port"`
	Password   string      `json:"password"`
	Method     string      `json:"method"`
	Prefix     string      `json:"prefix"`
	Name       string      `json:"name"`
}

// SSConfHTTPClient bounds the ssconf:// fetch. http.Client.Timeout covers the
// entire round trip (connect + TLS + headers + body read), so a black-holed or
// tarpitting endpoint degrades to a normal per-link error that the conversion
// loop skips, instead of stalling the WHOLE subscription conversion forever
// (the old bare http.Get used http.DefaultClient with zero timeout).
// Exported as a variable so tests can substitute an httptest TLS client.
var SSConfHTTPClient = &http.Client{Timeout: 10 * time.Second}

func fetchSSConf(parsedURL *url.URL) ([]byte, error) {

	// Construct the HTTP URL
	httpURL := "https://" + parsedURL.Host + parsedURL.Path

	// Make the HTTP request
	resp, err := SSConfHTTPClient.Get(httpURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
func parseAndFetchBeePass(body []byte) (*beepassData, error) {

	// Decode JSON
	var config beepassData
	err := json.Unmarshal(body, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func BeepassSingbox(beepassUrl string) (*T.Outbound, error) {
	parsedURL, err := url.Parse(beepassUrl)
	if err != nil {
		return nil, err
	}
	body, err := fetchSSConf(parsedURL)
	if err != nil {
		return nil, err
	}
	decoded, err := parseAndFetchBeePass(body)
	if err != nil {
		return ShadowsocksSingbox(strings.TrimSpace(string(body)))
		// return nil, err
	}
	// SIP008-список ({"version":1,"servers":[…]}) анмаршалится в beepassData
	// БЕЗ ошибки — все поля пустые → раньше выходил мусорный узел
	// server="" method="". Честная ошибка вместо тихого мусора.
	if decoded.Server == "" || decoded.Method == "" {
		return nil, fmt.Errorf("ssconf: body is not a single-server Outline config (server/method missing; SIP008 lists are not supported via ssconf://)")
	}
	// Тот же цензор шифров, что в ShadowsocksSingbox: невалидный метод должен
	// падать читаемо здесь, а не hinvalid-заглушкой на создании аутбаунда.
	method := normalizeSSMethod(decoded.Method)
	if !ssSupportedMethods[method] {
		return nil, fmt.Errorf("ssconf: shadowsocks cipher %q is not supported by the sing-box core", decoded.Method)
	}
	if decoded.Name == "" {
		decoded.Name = parsedURL.Fragment
	}
	result := T.Outbound{
		Type: "shadowsocks",
		Tag:  decoded.Name,
		Options: &T.ShadowsocksOutboundOptions{
			ServerOptions: T.ServerOptions{
				Server:     decoded.Server,
				ServerPort: toUInt16(decoded.ServerPort.String(), 443),
			},
			Method:   method,
			Password: decoded.Password,
		},
	}

	return &result, nil
}
