//go:build tools

// Этот файл никогда не компилируется (тег tools) — он только держит
// github.com/spf13/cobra в go.mod/go.sum core-модуля.
//
// Зачем: xray2sing/cmd (CLI конвертера) импортирует cobra, а vet/list в CI
// (.github/workflows/build.yml, MODULES) и по CLAUDE.md гоняются для
// github.com/twilgate/xray2sing/... ИЗ core/ — через replace, то есть по графу
// модулей core. До 2026-09-23 cobra держал в go.mod наш собственный CLI
// (core/cmd); его снесли, и `go mod tidy` (его зовёт `make prepare` →
// android/ios/windows-amd64) молча выкинул бы cobra — xray2sing/cmd перестал бы
// резолвиться, а CI-assert на неучтённые поломки покраснел бы.
//
// Удалять вместе с xray2sing/cmd, не раньше.
package hygiene

import _ "github.com/spf13/cobra"
