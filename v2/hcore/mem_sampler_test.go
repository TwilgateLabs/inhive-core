package hcore

import (
	"strings"
	"testing"
)

// Формат хвоста минутной строки mem: (longrun-аудит 2026-09-23 §5) — по этим
// ключам логи разбирают grep'ом; без туннеля менеджеры недоступны и поля
// обязаны деградировать в «-», а не паниковать.
func TestEngineLoadFields_FormatWithoutEngine(t *testing.T) {
	got := engineLoadFields(1.5, 10)
	for _, want := range []string{
		"gc_cpu=15.0%", "outbounds=", "endpoints=", "conns=", "resets=",
		"dials_inflight=", "dns_inflight=",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("engineLoadFields = %q, missing %q", got, want)
		}
	}
	if engineLoadFields(1, 0) == "" || !strings.HasPrefix(engineLoadFields(1, 0), "gc_cpu=0.0%") {
		t.Fatalf("zero CPU interval must give gc_cpu=0.0%%, got %q", engineLoadFields(1, 0))
	}
}
