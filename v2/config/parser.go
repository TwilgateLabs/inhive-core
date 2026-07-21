// parser.go — parses configs from URL, file, or content (JSON, YAML, Clash, V2Ray).
package config

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/batch"
	SJ "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
	"github.com/twilgate/xray2sing/ray2sing"
	"github.com/xmdhs/clash2singbox/convert"
	"github.com/xmdhs/clash2singbox/model/clash"
	"gopkg.in/yaml.v3"
)

//go:embed config.json.template
var configByte []byte

func ReadContent(ctx context.Context, opt *ReadOptions) ([]byte, error) {
	if opt.Content == "" {
		contentBytes, err := os.ReadFile(opt.Path)
		if err != nil {
			return nil, err
		}
		opt.Content = string(contentBytes)
	}
	return []byte(opt.Content), nil
}

func ParseConfig(ctx context.Context, opt *ReadOptions, debug bool, configOpt *InhiveOptions, fullConfig bool) (*option.Options, error) {
	content, err := ReadContent(ctx, opt)
	if err != nil {
		return nil, err
	}
	return parseConfigContent(ctx, content, debug, nil, false)
}

func ParseConfigBytes(ctx context.Context, opt *ReadOptions, debug bool, configOpt *InhiveOptions, fullConfig bool) ([]byte, error) {

	options, err := ParseConfig(ctx, opt, debug, configOpt, fullConfig)
	if err != nil {
		return nil, err
	}

	return options.MarshalJSONContext(ctx)

}
func parseConfigContent(ctx context.Context, content []byte, debug bool, configOpt *InhiveOptions, fullConfig bool) (*option.Options, error) {
	if configOpt == nil {
		configOpt = DefaultInhiveOptions()
	}

	// Порядок веток. (1) sing-box-native JSON — прямой unmarshal, lossless и
	// покрывает ВСЕ зарегистрированные типы (в отличие от URI-транскода ниже).
	// (2) ray2sing — share-link'и, base64 И json_ingest (Xray JSON / Happ /
	// SIP008 / sing-box-JSON через URI-обход). (3) clash YAML.
	//
	// До 2026-07-22 неудача JSON-ветки была ФАТАЛЬНОЙ: валидный JSON, который
	// не является sing-box-конфигом (Xray, SIP008, Happ-массив), не доходил до
	// ray2sing — хотя канонический coreParse-путь (mobile.Parse/desktop parse →
	// ray2sing.Ray2Singbox) его переваривает. На этом рассинхроне hot-add
	// (AddOutbound → сюда) падал там, где полная сборка работала. Теперь
	// JSON-ветка при неудаче ПРОВАЛИВАЕТСЯ в ray2sing, а её ошибка (самая
	// специфичная) возвращается, только если не сработал ни один парсер.
	var singboxJSONErr error
	var tmpJsonResult any
	jsonDecoder := json.NewDecoder(SJ.NewCommentFilter(bytes.NewReader(content)))
	if err := jsonDecoder.Decode(&tmpJsonResult); err == nil {
		fmt.Printf("Convert using json\n")
		options, err := parseSingboxJSON(ctx, tmpJsonResult, configOpt, fullConfig)
		if err == nil {
			return options, nil
		}
		singboxJSONErr = err
	}

	v2ray, err := ray2sing.Ray2SingboxOptions(ctx, string(content), configOpt.UseXrayCoreWhenPossible)

	if err == nil {
		return patchConfigOptions(ctx, v2ray, "V2rayParser", configOpt)
	}
	fmt.Printf("Convert using clash\n")
	clashObj := clash.Clash{}
	if err := yaml.Unmarshal(content, &clashObj); err == nil && clashObj.Proxies != nil {
		if len(clashObj.Proxies) == 0 {
			return nil, fmt.Errorf("[ClashParser] no outbounds found")
		}
		converted, err := convert.Clash2sing(clashObj)
		if err != nil {
			return nil, fmt.Errorf("[ClashParser] converting clash to sing-box error: %w", err)
		}
		output := configByte
		output, err = convert.Patch(output, converted, "", "", nil)
		if err != nil {
			return nil, fmt.Errorf("[ClashParser] patching clash config error: %w", err)
		}
		return patchConfigStr(ctx, output, "ClashParser", configOpt)
	}

	if singboxJSONErr != nil {
		return nil, singboxJSONErr
	}
	return nil, fmt.Errorf("unable to determine config format")
}

// parseSingboxJSON — sing-box-native ветка parseConfigContent: уже
// json-декодированный контент интерпретируется как sing-box конфиг / массив
// outbound'ов / ОДИНОЧНЫЙ outbound-или-endpoint объект.
//
// История: одиночный объект здесь оборачивался багом «jsonObj["outbounds"] =
// []interface{}{jsonObj}» — карта вкладывала СЕБЯ (пустую) вместо
// распарсенного tmpJsonObj. Цикл ронял json.MarshalIndent, ошибка глоталась
// через `_`, и UnmarshalJSONContext(nil) давал «[SingboxParser] unmarshal
// error: EOF» — тот самый EOF, из-за которого hot-add (AddOutbound) не ел
// servers из контейнерных подписок (их идентичность в app = одиночный
// sing-box outbound JSON, см. app/.../server_uri_parser.dart), хотя полная
// сборка те же серверы переваривала. 2026-07-22.
func parseSingboxJSON(ctx context.Context, tmpJsonResult any, configOpt *InhiveOptions, fullConfig bool) (*option.Options, error) {
	jsonObj := make(map[string]interface{})

	switch v := tmpJsonResult.(type) {
	case map[string]interface{}:
		if v["outbounds"] == nil && v["endpoints"] == nil {
			// Одиночный объект. wireguard/awg/tailscale в sing-box 1.13+ живут
			// в endpoints[], НЕ в outbounds[] — контейнер выбираем по реестру
			// типов из контекста (не хардкод: реестр = источник истины).
			// Типы, живущие в ОБОИХ реестрах (wireguard: endpoint + legacy
			// outbound), пробуем в обоих контейнерах — форма полей у поколений
			// разная (endpoint: address/peers, legacy outbound: local_address),
			// и решить по одному "type" нельзя.
			containers := []string{"outbounds"}
			if isEndpointType(ctx, v) {
				containers = []string{"endpoints", "outbounds"}
			}
			var firstErr error
			for _, container := range containers {
				candidate := map[string]interface{}{container: []interface{}{v}}
				newContent, err := json.MarshalIndent(candidate, "", "  ")
				if err != nil {
					return nil, fmt.Errorf("[SingboxParser] marshal error: %w", err)
				}
				options, err := patchConfigStr(ctx, newContent, "SingboxParser", configOpt)
				if err == nil {
					return options, nil
				}
				if firstErr == nil {
					firstErr = err
				}
			}
			return nil, firstErr
		} else if fullConfig || (configOpt != nil && configOpt.EnableFullConfig) {
			jsonObj = v
		} else {
			if v["outbounds"] != nil {
				jsonObj["outbounds"] = v["outbounds"]
			}
			if v["endpoints"] != nil {
				jsonObj["endpoints"] = v["endpoints"]
			}
		}
	case []interface{}:
		// Массив объектов. Раньше стоял type-assert на []map[string]interface{},
		// который для json.Decode НЕДОСТИЖИМ (массив всегда декодируется в
		// []interface{}) — любой массив падал в «Incorrect Json Format».
		// Элементы раскладываем по контейнерам так же, по реестру типов.
		if len(v) == 0 {
			return nil, fmt.Errorf("[SingboxParser] Incorrect Json Format")
		}
		var outbounds, endpoints []interface{}
		for _, item := range v {
			if m, ok := item.(map[string]interface{}); ok && isEndpointType(ctx, m) {
				endpoints = append(endpoints, item)
			} else {
				outbounds = append(outbounds, item)
			}
		}
		if len(outbounds) > 0 {
			jsonObj["outbounds"] = outbounds
		}
		if len(endpoints) > 0 {
			jsonObj["endpoints"] = endpoints
		}
	default:
		return nil, fmt.Errorf("[SingboxParser] Incorrect Json Format")
	}

	newContent, err := json.MarshalIndent(jsonObj, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("[SingboxParser] marshal error: %w", err)
	}

	return patchConfigStr(ctx, newContent, "SingboxParser", configOpt)
}

// isEndpointType — жив ли "type" объекта в endpoint-реестре sing-box.
// Endpoint-трактовка приоритетна: для типов, живущих в обоих реестрах
// (wireguard = endpoint И legacy outbound в 1.13), современная форма — это
// endpoints[]; legacy-форму догоняет ретрай во втором контейнере у caller'а.
func isEndpointType(ctx context.Context, obj map[string]interface{}) bool {
	typ, _ := obj["type"].(string)
	if typ == "" {
		return false
	}
	endpointRegistry := service.FromContext[option.EndpointOptionsRegistry](ctx)
	if endpointRegistry == nil {
		return false
	}
	_, isEndpoint := endpointRegistry.CreateOptions(typ)
	return isEndpoint
}

func patchConfigStr(ctx context.Context, content []byte, name string, configOpt *InhiveOptions) (*option.Options, error) {
	options := option.Options{}
	err := options.UnmarshalJSONContext(ctx, content)

	if err != nil {
		return nil, fmt.Errorf("[SingboxParser] unmarshal error: %w", err)
	}

	return patchConfigOptions(ctx, &options, name, configOpt)
}
func patchConfigOptions(ctx context.Context, options *option.Options, name string, configOpt *InhiveOptions) (*option.Options, error) {
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[*option.Endpoint](2))
	for _, base := range options.Endpoints {
		out := base
		b.Go(base.Tag, func() (*option.Endpoint, error) {
			err := patchWarp(&out, configOpt, false, nil)
			if err != nil {
				return nil, fmt.Errorf("[Warp] patch warp error: %w", err)
			}
			// options.Outbounds[i] = base
			return &out, nil
		})
	}
	if res, err := b.WaitAndGetResult(); err != nil {
		return nil, err
	} else {
		for i, base := range options.Endpoints {
			options.Endpoints[i] = *res[base.Tag].Value
		}
	}

	// fmt.Printf("%s\n", content)
	return validateResult(ctx, options, name)
}

func validateResult(ctx context.Context, options *option.Options, name string) (*option.Options, error) {
	err := libbox.CheckConfigOptions(options)
	if err != nil {
		return nil, fmt.Errorf("[%s] invalid sing-box config: %w", name, err)
	}
	return options, nil
}
