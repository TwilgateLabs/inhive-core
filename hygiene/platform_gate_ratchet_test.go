// Package hygiene содержит фитнес-функции (архитектурные ratchet-гейты) для core/.
// Тесты тут ничего не собирают и не запускают — только читают дерево исходников.
package hygiene

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// Ratchet-гейт: платформенное ветвление обязано нести обоснование «почему
// именно эти ОС».
//
// ЗАЧЕМ (аудит 2026-07-19). За один день нашли 5 экземпляров одного шаблона —
// платформенное ветвление сделано не на том уровне / не для тех ОС / его нет
// вовсе. Три класса дрейфа:
//
//	1. iOS-оптимизация БЕЗ гейта течёт на все платформы. SetGCPercent(30)
//	   физически стоял строкой ВЫШЕ `if C.IsIos`, при том что комментарий ниже
//	   гласил «Android/Windows не трогаем». Намерение задокументировано —
//	   код делал обратное.
//	2. Гейт `ios` там, где по смыслу `mobile` → Android систематически
//	   недополучает (heartbeat off, closedConnectionsLimit).
//	3. macOS/Linux выпали из циклов фиксов вообще.
//
// Цена одного экземпляра: Windows полгода жил на неправильном TUN-стеке —
// задержка 2991мс вместо 139.
//
// ПРАВИЛО (утверждено Никитой 2026-07-19): любое платформенное ветвление
// обязано нести рядом комментарий, объясняющий выбор ОС. Комментарий засчитан,
// если он стоит вплотную сверху, хвостом на той же строке или первыми строками
// внутри блока — то есть там, где его увидит следующий читатель гейта.
//
// Ratchet проверяет НАЛИЧИЕ комментария, а не его смысл: смысл — работа ревью.
// Механическая часть ловит ровно тот случай, который нас укусил, — гейт,
// поставленный молча.
// ─────────────────────────────────────────────────────────────────────────────

// baseline — сколько НЕпрокомментированных платформенных гейтов сейчас в дереве.
//
// Зафиксировано 2026-07-19 по факту прогона сканера (не «0 и посмотрим»).
// Число = количество мест, где ветвление по ОС стоит без обоснования рядом.
// Основная масса — унаследованный upstream sing-box, который мы не писали;
// наш собственный код (v2/) в этот долг вносит меньшую часть.
//
// ПРАВИЛО РАТЧЕТА: значения тут двигаются ТОЛЬКО ВНИЗ.
// Прокомментировал гейт — опусти число. Тест сам подскажет новое.
//
// Поднимать baseline можно только осознанно и с обоснованием в ревью: это
// означает «мы сознательно добавили платформенное ветвление и сознательно
// решили не объяснять, почему именно эти ОС». Такое решение должно быть
// видно человеку в диффе, а не проскочить молча.
var baseline = map[string]int{
	"v2":        10, // наш код: 8 инлайновых C.Is*/runtime.GOOS + 1 build-тег
	"sing-box":  34, // унаследованный апстрим + наши патчи поверх
	"cmd":       0,
	"platform":  0,
	"xray2sing": 0,
}

// totalBaseline ловит новые гейты вне каталогов, перечисленных выше.
const totalBaseline = 44

// ─────────────────────────────────────────────────────────────────────────────
// Что сканер СОЗНАТЕЛЬНО не смотрит.
// ─────────────────────────────────────────────────────────────────────────────

// skipDirs — каталоги, целиком выпадающие из скана.
//
// Ключевое: `sing-box/replace/*` — вендоренные апстрим-форки (x-net,
// quic-go, tailscale, wireguard-go, psiphon-tls), это чужой код, мы его не
// пишем и комментировать чужие build-теги смысла нет (там одних только
// платформенных тегов больше двух тысяч файлов — тест бы утонул в шуме).
// Наши правки в этих форках всё равно проходят ревью отдельно.
var skipDirs = map[string]bool{
	".git":         true,
	".github":      true,
	".claude":      true, // worktrees агентов — копии дерева, дали бы двойной счёт
	"node_modules": true,
	"bin":          true,
	"build":        true,
	"release":      true,
	"scratch":      true,
	"docs":         true,
	"assets":       true,
	"maybenot":     true, // не Go
	"testdata":     true,
}

// skipPathSuffixes — поддеревья, которые отсекаем по пути (не по имени папки).
var skipPathSuffixes = []string{
	"sing-box/replace",      // вендоренные форки апстрима — чужой код
	"sing-box/test",         // интеграционные тесты апстрима
	"sing-box/cmd/internal", // build-тулинг: там runtime.GOOS — это ОС билд-хоста,
	// а не таргета. Другой класс, в наш баг-паттерн не входит.
}

// ─────────────────────────────────────────────────────────────────────────────
// Распознавание гейтов.
// ─────────────────────────────────────────────────────────────────────────────

// constGate — инлайновая константа платформы из sing-box constant:
// C.IsIos / C.IsAndroid / C.IsDarwin / C.IsWindows / C.IsLinux.
// Это ровно тот тип ветвления, на котором нас укусило пять раз.
var constGate = regexp.MustCompile(`\bC\.Is(Ios|Android|Darwin|Windows|Linux)\b`)

// goosCompare — сравнение runtime.GOOS со строкой.
//
// Голый runtime.GOOS без сравнения (User-Agent, строка версии, путь к NDK) —
// не ветвление, а подстановка. Такое не считаем: это был бы чистый шум.
var goosCompare = regexp.MustCompile(`runtime\.GOOS\s*[!=]=|[!=]=\s*runtime\.GOOS|switch\s+runtime\.GOOS`)

// buildTag — директива ограничения сборки.
var buildTag = regexp.MustCompile(`^//go:build\s+(.*)$`)

// tagToken — идентификатор в build-констрейнте, с учётом отрицания.
var tagToken = regexp.MustCompile(`(!?)\s*([a-z0-9_.]+)`)

// osTerms — GOOS-значения и мета-теги, которые считаем платформенными.
// Всё остальное в build-теге (with_quic, cgo, go1.25, badlinkname, daita,
// generate) — фича-флаги и режимы сборки, к «почему именно эти ОС» отношения
// не имеют.
var osTerms = map[string]bool{
	"android": true, "darwin": true, "ios": true, "linux": true,
	"windows": true, "freebsd": true, "openbsd": true, "netbsd": true,
	"dragonfly": true, "solaris": true, "illumos": true, "aix": true,
	"plan9": true, "js": true, "wasip1": true, "zos": true, "hurd": true,
	"unix": true,
}

// osFileSuffix — конвенция Go: foo_windows.go собирается только под windows.
// Имя файла тут само себе документация, требовать сверху комментарий «почему
// windows» — шум.
var osFileSuffix = regexp.MustCompile(`_(android|darwin|ios|linux|windows|freebsd|openbsd|netbsd|dragonfly|solaris|illumos|aix|plan9|js|wasip1|zos|hurd|unix)(_[a-z0-9]+)?\.go$`)

// fallbackFile — вторая половина платформенного сплита по конвенции Go:
// redir_linux.go + redir_darwin.go + redir_other.go, foo_linux.go + foo_stub.go.
//
// Их build-тег («всё кроме linux и darwin») не несёт самостоятельного решения:
// он механически дополняет позитивные файлы, и настоящий ответ на «почему
// именно эти ОС» лежит в них. Требовать комментарий здесь — ровно тот шум,
// из-за которого фитнес-функции выключают: 18 находок из 24 по build-тегам
// были именно такими заглушками, и ни одна из них никогда не будет
// прокомментирована.
//
// Инлайновые гейты внутри таких файлов при этом СЧИТАЮТСЯ — исключение
// касается только строки //go:build.
var fallbackFile = regexp.MustCompile(`(^|_)(stub|other|unsupported|fallback|generic)(_[a-z0-9]+)?\.go$`)

// finding — один непрокомментированный гейт.
type finding struct {
	path string // относительно core/
	line int    // 1-based
	kind string
	text string
}

// ─────────────────────────────────────────────────────────────────────────────
// Проверка «есть ли рядом обоснование».
// ─────────────────────────────────────────────────────────────────────────────

// isCommentLine — строка целиком комментарий.
func isCommentLine(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") || strings.HasPrefix(t, "*")
}

// isDirectiveComment — служебная директива, а не объяснение.
// `//go:build`, `// +build`, `//go:generate`, `//nolint` не являются
// обоснованием выбора ОС, засчитывать их нельзя — иначе каждый build-тег
// «объяснял» бы сам себя.
func isDirectiveComment(s string) bool {
	t := strings.TrimSpace(s)
	return strings.HasPrefix(t, "//go:") ||
		strings.HasPrefix(t, "// +build") ||
		strings.HasPrefix(t, "//nolint") ||
		strings.HasPrefix(t, "//line")
}

// trailingComment — хвостовой комментарий на самой строке гейта.
// Отсекаем `://` (URL внутри строкового литерала).
func trailingComment(s string) string {
	i := strings.Index(s, "//")
	if i <= 0 {
		return ""
	}
	if s[i-1] == ':' {
		return ""
	}
	return strings.TrimSpace(s[i+2:])
}

// platformMention — комментарий засчитывается, только если в нём НАЗВАНА
// платформа.
//
// Это разница между «что делает код» и «почему именно эти ОС» — а требование
// именно второе. Проверка на простое наличие комментария пропускала гейты, над
// которыми висел подробный рассказ про саму фичу и ни слова про выбор ОС.
//
// Обойти проверку тривиально — но только осознанно, а кусали нас именно молча
// поставленные гейты.
var platformMention = regexp.MustCompile(
	`(?i)\b(windows|android|ios|ipados|macos|darwin|linux|unix|desktop|mobile|winapi|win32|netlink|jetsam)\b` +
		`|десктоп|мобильн|платформ|андроид|виндов|винде|винды`)

// commentBlockUp — сплошной блок комментариев вверх от строки i.
// Объяснение может стоять не в той строке, на которую мы наткнулись.
func commentBlockUp(lines []string, i int) string {
	var buf []string
	for j := i; j >= 0 && isCommentLine(lines[j]); j-- {
		buf = append(buf, lines[j])
	}
	return strings.Join(buf, " ")
}

// commentBlockDown — сплошной блок комментариев вниз от строки i.
func commentBlockDown(lines []string, i int) string {
	var buf []string
	for j := i; j < len(lines) && isCommentLine(lines[j]); j++ {
		buf = append(buf, lines[j])
	}
	return strings.Join(buf, " ")
}

// statementHead — начало инструкции, в которой стоит гейт.
//
// Условие часто разложено на несколько строк, а комментарий лежит над ПЕРВОЙ.
// Без подъёма к голове инструкции прекрасно документированный гейт считался бы
// молчаливым — ровно тот ложняк, который превращает фитнес-функцию в шум.
//
// Поднимаемся строго по признакам продолжения выражения (оператор в конце
// предыдущей строки или в начале текущей), а НЕ «пока не встретим `;`»: второе
// уводит вверх по composite literal'ам на произвольную глубину.
func statementHead(lines []string, idx int) int {
	// `,` и `(` сюда НЕ входят намеренно: с ними подъём уползает вверх по
	// composite literal'у на произвольную глубину, и находка указывает на
	// строку вообще без гейта (`Rules: routeRules,` вместо
	// `AutoDetectInterface: (!C.IsAndroid && !C.IsIos) && …`).
	tailOps := []string{"&&", "||", "=", "+"}
	headOps := []string{"&&", "||", ".", "+"}

	head := idx
	for head > 0 {
		j := head - 1
		for j >= 0 && strings.TrimSpace(lines[j]) == "" {
			j--
		}
		if j < 0 {
			break
		}
		prev := strings.TrimSpace(lines[j])
		if isCommentLine(prev) {
			break // комментарий и есть шапка инструкции
		}
		cur := strings.TrimSpace(lines[head])
		cont := false
		for _, op := range tailOps {
			if strings.HasSuffix(prev, op) {
				cont = true
				break
			}
		}
		if !cont {
			for _, op := range headOps {
				if strings.HasPrefix(cur, op) {
					cont = true
					break
				}
			}
		}
		if !cont {
			break
		}
		head = j
	}
	return head
}

// predicateOf — нормализованный платформенный предикат строки.
//
// Нужен, чтобы схлопывать ОДНУ И ТУ ЖЕ политику, повторённую в файле
// механически: `if !C.IsLinux { … }` в начале каждого из пяти методов — это
// одно решение, а не пять, и требовать пять одинаковых комментариев значит
// генерировать шум. Разные предикаты в одном файле остаются разными находками.
func predicateOf(line string) string {
	var tokens []string
	for _, m := range regexp.MustCompile(`(!?)\s*C\.Is(\w+)`).FindAllStringSubmatch(line, -1) {
		tokens = append(tokens, m[1]+m[2])
	}
	for _, m := range regexp.MustCompile(`runtime\.GOOS\s*([!=]=)\s*"(\w+)"`).FindAllStringSubmatch(line, -1) {
		tokens = append(tokens, m[1]+m[2])
	}
	if len(tokens) == 0 {
		return strings.TrimSpace(line)
	}
	sort.Strings(tokens)
	return strings.Join(tokens, "|")
}

// elseChain — `} else if …` продолжает решение, принятое выше: исчерпывающий
// диспатч по пяти ОС — это ОДИН выбор, а не пять. Голова цепочки уже посчитана.
var elseChain = regexp.MustCompile(`^\}?\s*else\b`)

// hasJustification — есть ли обоснование рядом с гейтом на строке idx (0-based).
//
// Засчитываем три позиции, потому что все три реально встречаются в этом
// дереве и все три читаются человеком, который смотрит на гейт:
//   - блок комментариев вплотную сверху (через максимум одну пустую строку);
//   - хвост на самой строке;
//   - первые строки ВНУТРИ блока — так написан, например, самый аккуратно
//     задокументированный гейт репо (libbox/memory.go: `if C.IsIos {`, а
//     объяснение — следующими строками внутри).
func hasJustification(lines []string, idx int) bool {
	if platformMention.MatchString(trailingComment(lines[idx])) {
		return true
	}

	// Вверх: пропускаем не более одной пустой строки и не более одного
	// открывающего блок уровня — комментарий часто висит над ОХВАТЫВАЮЩИМ
	// блоком, а гейт стоит первой строкой внутри. Читатель гейта его видит.
	blanks, openerSkips := 0, 0
	for i := idx - 1; i >= 0 && i >= idx-6; i-- {
		t := strings.TrimSpace(lines[i])
		if t == "" {
			blanks++
			if blanks > 1 {
				break
			}
			continue
		}
		if isCommentLine(t) {
			if isDirectiveComment(t) {
				continue // над build-тегом может лежать другой build-тег
			}
			return platformMention.MatchString(commentBlockUp(lines, i))
		}
		if strings.HasSuffix(t, "{") && openerSkips == 0 {
			openerSkips++
			continue
		}
		break // наткнулись на код — обоснования сверху нет
	}

	// Вниз: первые две строки внутри блока.
	for i := idx + 1; i < len(lines) && i <= idx+2; i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" {
			continue
		}
		if isCommentLine(t) {
			if isDirectiveComment(t) {
				continue
			}
			return platformMention.MatchString(commentBlockDown(lines, i))
		}
		break
	}

	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Сканер.
// ─────────────────────────────────────────────────────────────────────────────

// isPlatformBuildTag решает, требует ли build-констрейнт обоснования.
//
// Логика: вытаскиваем из констрейнта только платформенные термы.
//   - нет платформенных термов (`with_quic`, `go1.25 && badlinkname`) →
//     это не платформенный гейт, пропускаем;
//   - ровно один положительный терм (`linux`, `darwin && cgo`) → структурное
//     разделение по конвенции Go, имя файла говорит то же самое, пропускаем;
//   - всё остальное (`!windows`, `linux && !android`, `!ios && darwin`,
//     `(!linux && !windows) || android`) → это уже выбор подмножества ОС,
//     то есть ровно тот судейский вызов, который надо объяснять.
func isPlatformBuildTag(constraint string) bool {
	var terms []string
	negated := false
	for _, m := range tagToken.FindAllStringSubmatch(constraint, -1) {
		if !osTerms[m[2]] {
			continue
		}
		terms = append(terms, m[2])
		if m[1] == "!" {
			negated = true
		}
	}
	if len(terms) == 0 {
		return false
	}
	if len(terms) == 1 && !negated {
		return false
	}
	return true
}

func shouldSkipPath(rel string) bool {
	for _, suf := range skipPathSuffixes {
		if rel == suf || strings.HasPrefix(rel, suf+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// scanFile возвращает непрокомментированные гейты одного файла.
func scanFile(root, path string) ([]finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	rel, _ := filepath.Rel(root, path)

	// Сгенерированный код не наш — комментировать его бессмысленно,
	// при следующей регенерации комментарий всё равно пропадёт.
	for i := 0; i < len(lines) && i < 8; i++ {
		if strings.Contains(lines[i], "Code generated") {
			return nil, nil
		}
	}

	base := filepath.Base(path)
	fileIsOSSpecific := osFileSuffix.MatchString(base) || fallbackFile.MatchString(base)

	var out []finding
	inBlockComment := false
	seenHeads := map[int]bool{}
	seenPredicates := map[string]bool{}
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Блочные комментарии /* ... */ — содержимое не код.
		if inBlockComment {
			if strings.Contains(line, "*/") {
				inBlockComment = false
			}
			continue
		}
		if strings.HasPrefix(trimmed, "/*") && !strings.Contains(line, "*/") {
			inBlockComment = true
			continue
		}

		// build-теги обрабатываем до отсечки строк-комментариев:
		// //go:build сам по себе выглядит комментарием.
		if m := buildTag.FindStringSubmatch(trimmed); m != nil {
			if fileIsOSSpecific {
				// foo_linux.go / foo_other.go — имя файла и есть объяснение
				continue
			}
			if !isPlatformBuildTag(m[1]) {
				continue
			}
			if !hasJustification(lines, i) {
				out = append(out, finding{rel, i + 1, "build-tag", trimmed})
			}
			continue
		}

		// Закомментированный код — не гейт. Ровно это отсекает мёртвые
		// `// if opt.EnableTun && runtime.GOOS == "android" {` в builder_route.go.
		if strings.HasPrefix(trimmed, "//") {
			continue
		}

		// `} else if C.IsX` продолжает решение, принятое выше.
		if elseChain.MatchString(trimmed) {
			continue
		}

		var kind string
		switch {
		case constGate.MatchString(line):
			kind = "C.Is*"
		case goosCompare.MatchString(line):
			kind = "runtime.GOOS"
		default:
			continue
		}

		// Многострочное условие — считаем один раз, по голове инструкции.
		head := statementHead(lines, i)
		if seenHeads[head] {
			continue
		}
		seenHeads[head] = true
		pred := predicateOf(line)
		if seenPredicates[pred] {
			continue
		}
		seenPredicates[pred] = true

		if !hasJustification(lines, head) {
			out = append(out, finding{rel, head + 1, kind, strings.TrimSpace(lines[head])})
		}
	}
	return out, nil
}

// scanTree обходит core/ и собирает все непрокомментированные гейты.
func scanTree(root string) ([]finding, error) {
	var all []finding
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil
		}
		if info.IsDir() {
			if path != root && (skipDirs[info.Name()] || shouldSkipPath(rel)) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.HasSuffix(path, ".pb.go") || strings.HasSuffix(path, "_grpc.pb.go") {
			return nil
		}
		found, scanErr := scanFile(root, path)
		if scanErr != nil {
			return scanErr
		}
		all = append(all, found...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].path != all[j].path {
			return all[i].path < all[j].path
		}
		return all[i].line < all[j].line
	})
	return all, nil
}

// areaOf — верхний каталог, к которому относим находку.
func areaOf(rel string) string {
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) > 0 {
		return parts[0]
	}
	return "."
}

// coreRoot — корень модуля core/ (тест лежит в core/hygiene).
func coreRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("не определить корень core/: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("в %s нет go.mod — тест лежит не там, где ожидалось", root)
	}
	return root
}

func formatFindings(fs []finding) string {
	var b strings.Builder
	for _, f := range fs {
		text := f.text
		if len(text) > 100 {
			text = text[:100] + "…"
		}
		fmt.Fprintf(&b, "  core/%s:%d  [%s]  %s\n", f.path, f.line, f.kind, text)
	}
	return b.String()
}

const howToFix = `
Как чинить: рядом с каждым гейтом нужен комментарий «почему именно эти ОС».
Не «что делает код» — а почему список ОС именно такой и что сломается на
остальных. Пример из этого репо (libbox/memory.go):

    if C.IsIos {
        // Почему именно iOS: смысл у этого числа появляется исключительно в
        // паре с SetMemoryLimit(32MB) — удержать RSS под ~45MB, чтобы jetsam
        // не убил packet-tunnel с бюджетом 50MB.

Место для комментария: вплотную сверху, хвостом на строке или первыми
строками внутри блока — любое засчитывается.

Если гейт добавлен осознанно и объяснять нечего — подними baseline в
core/hygiene/platform_gate_ratchet_test.go, это будет видно в ревью.`

// ─────────────────────────────────────────────────────────────────────────────
// Тесты.
// ─────────────────────────────────────────────────────────────────────────────

func TestPlatformGateRatchet(t *testing.T) {
	root := coreRoot(t)
	all, err := scanTree(root)
	if err != nil {
		t.Fatalf("скан дерева упал: %v", err)
	}

	byArea := map[string][]finding{}
	for _, f := range all {
		area := areaOf(f.path)
		byArea[area] = append(byArea[area], f)
	}

	// PLATFORM_GATE_DUMP=1 go test ./hygiene/ -run TestPlatformGateRatchet -v
	// — печатает все находки целиком. Нужно, когда двигаешь baseline.
	if os.Getenv("PLATFORM_GATE_DUMP") != "" {
		areas := make([]string, 0, len(byArea))
		for a := range byArea {
			areas = append(areas, a)
		}
		sort.Strings(areas)
		for _, a := range areas {
			t.Logf("=== %s: %d ===\n%s", a, len(byArea[a]), formatFindings(byArea[a]))
		}
		t.Logf("=== ВСЕГО: %d ===", len(all))
	}

	for area, limit := range baseline {
		t.Run(area, func(t *testing.T) {
			got := byArea[area]
			if len(got) <= limit {
				return
			}
			t.Errorf(
				"В core/%s непрокомментированных платформенных гейтов стало больше: %d → %d.\n"+
					"Платформенное ветвление обязано нести рядом комментарий «почему именно эти ОС»\n"+
					"(правило утверждено 2026-07-19 после того, как Windows полгода жил на неправильном\n"+
					"TUN-стеке — 2991мс задержки вместо 139).\n\n"+
					"Все непрокомментированные гейты в core/%s:\n%s%s",
				area, limit, len(got), area, formatFindings(got), howToFix,
			)
		})
	}

	t.Run("всего по core/", func(t *testing.T) {
		if len(all) <= totalBaseline {
			return
		}
		// Показываем только то, что вне известных каталогов, — иначе дубль.
		var unknown []finding
		for _, f := range all {
			if _, known := baseline[areaOf(f.path)]; !known {
				unknown = append(unknown, f)
			}
		}
		msg := fmt.Sprintf(
			"Общий счётчик непрокомментированных платформенных гейтов по core/ вырос: %d → %d.",
			totalBaseline, len(all),
		)
		if len(unknown) > 0 {
			msg += fmt.Sprintf("\n\nГейты вне каталогов из baseline:\n%s", formatFindings(unknown))
		}
		t.Errorf("%s%s", msg, howToFix)
	})
}

// TestPlatformGateRatchetBaselineNotStale ловит обратную ошибку: гейты
// прокомментировали, а baseline забыли опустить. Без этого ratchet со временем
// протухает — цифра остаётся высокой и перестаёт что-либо ловить.
func TestPlatformGateRatchetBaselineNotStale(t *testing.T) {
	root := coreRoot(t)
	all, err := scanTree(root)
	if err != nil {
		t.Fatalf("скан дерева упал: %v", err)
	}

	counts := map[string]int{}
	for _, f := range all {
		counts[areaOf(f.path)]++
	}

	for area, limit := range baseline {
		if got := counts[area]; got < limit {
			t.Errorf(
				"baseline для core/%s протух: стоит %d, фактически %d. "+
					"Опусти значение до %d в core/hygiene/platform_gate_ratchet_test.go — "+
					"ratchet крутится только вниз.",
				area, limit, got, got,
			)
		}
	}
	if len(all) < totalBaseline {
		t.Errorf(
			"totalBaseline протух: стоит %d, фактически %d. Опусти до %d.",
			totalBaseline, len(all), len(all),
		)
	}
}
