// config.go — reads and processes sing-box configuration options.
package config

import (
	context "context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/sagernet/sing-box/experimental/libbox"
	"github.com/sagernet/sing-box/option"
)

type ReadOptions struct {
	Path    string
	Content string
	Options *option.Options
}

// SalvageLogf — куда салвейдж сохранённого профиля пишет о выброшенных
// записях. hcore перенаправляет это в shared-лог (вкладка «Логи»), чтобы
// дроп был наблюдаемым (правило: невидимых отказов не бывает).
var SalvageLogf = func(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func ReadSingOptions(ctx context.Context, opt *ReadOptions) (*option.Options, error) {
	if opt.Options != nil {
		return opt.Options, nil
	}
	content, err := ReadContent(ctx, opt)
	if err != nil {
		return nil, err
	}
	var options option.Options
	err = options.UnmarshalJSONContext(ctx, content)
	if err != nil {
		// Салвейдж: сохранённый профиль реплеится на КАЖДОМ старте, и одна
		// невалидная запись (тип, удалённый новым ядром; строгое поле) без
		// этого убивала все сервера до самой create-фазы, где действует
		// hinvalid-fallback. Дропаем только невалидные записи; ноль выживших —
		// честная ошибка (возвращаем исходную).
		if salvaged, serr := salvageSingOptions(ctx, content); serr == nil {
			return salvaged, nil
		}
		return &options, err
	}
	return &options, nil
}

// salvageSingOptions пере-декодирует конфиг с per-entry изоляцией outbounds и
// endpoints: каждая запись прогоняется через ТОТ ЖЕ строгий Options-анмаршал
// (semantics parity, включая DisallowUnknownFields), невалидные выбрасываются
// с логом. Висячие теги в selector/urltest после дропа чистит групповой линт
// в box.New. Ошибки вне outbounds/endpoints не лечатся — они возвращаются
// вызывающему как есть.
func salvageSingOptions(ctx context.Context, content []byte) (*option.Options, error) {
	var shallow map[string]json.RawMessage
	if err := json.Unmarshal(content, &shallow); err != nil {
		return nil, err
	}
	dropped := 0
	for _, section := range []string{"outbounds", "endpoints"} {
		raw, ok := shallow[section]
		if !ok {
			continue
		}
		var entries []json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, err
		}
		kept := entries[:0]
		for i, entry := range entries {
			probe := []byte(fmt.Sprintf(`{%q:[%s]}`, section, entry))
			var testOpts option.Options
			if err := testOpts.UnmarshalJSONContext(ctx, probe); err != nil {
				tag := entryTag(entry, i)
				SalvageLogf("start salvage: dropped %s[%s]: %v", section, tag, err)
				dropped++
				continue
			}
			kept = append(kept, entry)
		}
		rebuilt, err := json.Marshal(kept)
		if err != nil {
			return nil, err
		}
		shallow[section] = rebuilt
	}
	if dropped == 0 {
		return nil, fmt.Errorf("salvage: no droppable entries found")
	}
	rebuilt, err := json.Marshal(shallow)
	if err != nil {
		return nil, err
	}
	var options option.Options
	if err := options.UnmarshalJSONContext(ctx, rebuilt); err != nil {
		return nil, err
	}
	if len(options.Outbounds) == 0 && len(options.Endpoints) == 0 {
		return nil, fmt.Errorf("salvage: no outbounds survived")
	}
	SalvageLogf("start salvage: profile loaded with %d dropped entries", dropped)
	return &options, nil
}

func entryTag(entry json.RawMessage, index int) string {
	var meta struct {
		Tag  string `json:"tag"`
		Type string `json:"type"`
	}
	if json.Unmarshal(entry, &meta) == nil && meta.Tag != "" {
		return meta.Tag + "/" + meta.Type
	}
	return fmt.Sprintf("#%d", index)
}
func BuildConfigJson(ctx context.Context, configOpt *InhiveOptions, input *ReadOptions) ([]byte, error) {
	options, err := BuildConfig(ctx, configOpt, input)
	if err != nil {
		return nil, err
	}
	if err := libbox.CheckConfigOptions(options); err != nil {
		return nil, err
	}

	return options.MarshalJSONContext(ctx)

}
func ParseBuildConfigBytes(ctx context.Context, hopts *InhiveOptions, input *ReadOptions) ([]byte, error) {

	options, err := ParseBuildConfig(ctx, hopts, input)
	if err != nil {
		return nil, err
	}
	return options.MarshalJSONContext(ctx)
}
func ParseBuildConfig(ctx context.Context, hopts *InhiveOptions, input *ReadOptions) (*option.Options, error) {
	options := input.Options
	if options == nil {
		var err error
		options, err = ParseConfig(ctx, input, false, hopts, false)
		if err != nil {
			return nil, err
		}

	}
	return BuildConfig(ctx, hopts, &ReadOptions{Options: options})
}
