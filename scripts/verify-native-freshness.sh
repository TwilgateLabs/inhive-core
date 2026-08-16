#!/usr/bin/env bash
# verify-native-freshness.sh — ловит нативный артефакт, который СТАРШЕ кода ядра.
#
# ЗАЧЕМ (инцидент 2026-08-10/11)
# ------------------------------
# Никита: «4 обхода Reality не работают, и на 4.8.2 тоже». Замер против исходников
# говорил, что на 4.8.2 обязано работать. Оба были правы: REALITY-фиксы легли в ядро
# 2026-08-04 00:53/01:04, а `app/ios/Frameworks/InhiveCore.xcframework` был собран
# 2026-08-01 16:36 — на ТРИ ДНЯ раньше. iOS-сборка с `version: 4.8.2` несла Go-ядро,
# которое всё ещё объявляло REALITY-версию 1.8.1, и сервера с дефолтным порогом
# (Xray v26.3.27) молча её отвергали.
#
# Почему это не ловилось глазами:
#   * версия в «О приложении» берётся из pubspec.yaml и про Go-ядро НИЧЕГО не знает,
#     поэтому UI честно показывал свежий номер поверх старого ядра;
#   * iOS не в пайплайне `/release` (там Android APK + Windows), значит `make ios`
#     никто не дёргает автоматически — артефакт отстаёт молча и неограниченно долго.
# Ровно feedback_meta_unreportable_bug_class: отказ невидим ⇒ обязан стать наблюдаемым.
#
# ⚠️ ПОЧЕМУ СРАВНИВАЕМ С ДВУМЯ ИСТОРИЯМИ, А НЕ С ОДНОЙ
# Тот самый фикс лежал в САБМОДУЛЕ `core/sing-box`, а не в `core/`. Пока указатель
# сабмодуля не закоммичен в core, HEAD самого core может быть заметно старше реального
# кода. Поэтому берём МАКСИМУМ из (core HEAD, core/sing-box HEAD) — иначе гейт
# пропустит ровно тот класс, ради которого написан.
#
# Использование:
#   core/scripts/verify-native-freshness.sh ios       # xcframework (Mac)
#   core/scripts/verify-native-freshness.sh android   # AAR, если задеплоен локально
#   core/scripts/verify-native-freshness.sh all       # всё, что найдено
# Exit 0 — свежее; exit 1 — протухло или отсутствует; exit 2 — ошибка запуска.

set -uo pipefail

TARGET="${1:-all}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$(cd "$HERE/.." && pwd)"
REPO_ROOT="$(cd "$CORE_DIR/.." && pwd)"
APP_DIR="$REPO_ROOT/app"

XCFRAMEWORK="$APP_DIR/ios/Frameworks/InhiveCore.xcframework/ios-arm64/InhiveCore.framework/InhiveCore"
AAR="$APP_DIR/android/app/libs/inhive-core.aar"

fail=0

# ── epoch последнего коммита, максимум по core и его сабмодулю ──────────────────
core_epoch=$(git -C "$CORE_DIR" log -1 --format=%ct 2>/dev/null || echo 0)
sb_epoch=$(git -C "$CORE_DIR/sing-box" log -1 --format=%ct 2>/dev/null || echo 0)
if [ "$core_epoch" = "0" ] && [ "$sb_epoch" = "0" ]; then
  echo "verify-native-freshness: не смог прочитать git-историю ядра — проверка невозможна" >&2
  exit 2
fi
newest_epoch=$core_epoch
newest_src="core"
if [ "$sb_epoch" -gt "$newest_epoch" ]; then
  newest_epoch=$sb_epoch
  newest_src="core/sing-box"
fi

human() { date -r "$1" "+%Y-%m-%d %H:%M" 2>/dev/null || date -d "@$1" "+%Y-%m-%d %H:%M" 2>/dev/null; }

# mtime файла, портируемо между BSD (macOS) и GNU
mtime_of() { stat -f %m "$1" 2>/dev/null || stat -c %Y "$1" 2>/dev/null; }

echo "Свежесть нативных артефактов относительно кода ядра"
echo "  последний коммит: $(human "$newest_epoch")  (в $newest_src)"
echo

check() {
  local label="$1" path="$2" rebuild="$3"
  if [ ! -f "$path" ]; then
    printf '  %-12s ОТСУТСТВУЕТ — %s\n' "$label" "$path"
    printf '  %-12s пересобрать: %s\n\n' "" "$rebuild"
    fail=1
    return
  fi
  local m; m=$(mtime_of "$path")
  if [ -z "$m" ]; then
    printf '  %-12s не смог прочитать mtime: %s\n\n' "$label" "$path"
    fail=1
    return
  fi
  if [ "$m" -lt "$newest_epoch" ]; then
    local lag=$(( (newest_epoch - m) / 3600 ))
    printf '  %-12s ❌ ПРОТУХ — собран %s, это на %sч СТАРШЕ кода ядра\n' "$label" "$(human "$m")" "$lag"
    printf '  %-12s артефакт не содержит последних правок ядра. Пересобрать: %s\n\n' "" "$rebuild"
    fail=1
  else
    printf '  %-12s ✅ свежий — собран %s\n\n' "$label" "$(human "$m")"
  fi
}

case "$TARGET" in
  ios)     check "iOS"     "$XCFRAMEWORK" "cd core && make ios" ;;
  android) check "Android" "$AAR"         "cd core && make android" ;;
  all)
    check "iOS" "$XCFRAMEWORK" "cd core && make ios"
    # Android-артефакт обычно собирается на Win-сборщике и на маке его может не быть —
    # это не повод падать при `all`, поэтому проверяем только если он тут есть.
    if [ -f "$AAR" ]; then
      check "Android" "$AAR" "cd core && make android"
    else
      printf '  %-12s пропущен — AAR на этой машине не задеплоен (собирается на Win)\n\n' "Android"
    fi
    ;;
  *)
    echo "неизвестная цель: $TARGET (ожидается ios | android | all)" >&2
    exit 2
    ;;
esac

if [ "$fail" -ne 0 ]; then
  echo "ГЕЙТ НЕ ПРОЙДЕН: нативный артефакт старше кода ядра."
  echo "Версия в pubspec.yaml про Go-ядро НЕ знает — собранное приложение покажет"
  echo "свежий номер поверх старого ядра, и отказ будет невидим (инцидент 2026-08-10)."
  exit 1
fi

echo "ГЕЙТ ПРОЙДЕН."
