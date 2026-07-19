#!/usr/bin/env python3
"""
check-upstream-drift — сверяет вендоренный код InHive core с апстримами.

ЗАЧЕМ
-----
2026-07-19 полдня диагностики ушло на сравнение с копией Xray, отставшей на
6 релизов, и это породило ЛОЖНЫЙ ФИКС (xmux maxConcurrency 1..1 из 26.1.13
против maxConnections 6..6 из 26.7.11 — противоположные стратегии).
Корневая проблема: у лежащей рядом копии апстрима нет версии, и никто не
проверял, какая она.

Поэтому скрипт делает ДВЕ вещи, и первая важнее второй:

  1. ВЕРИФИЦИРУЕТ ЭТАЛОН. Для каждой записи резолвит записанный тег в СЕТИ и
     сверяет с записанным коммитом. Расхождение = либо апстрим перетегирован,
     либо в реестре записана не та версия. Это FAIL уровня «стоп, не сравнивай
     код, пока не разберёшься» — отдельный код возврата, громче обычного
     отставания.

  2. Считает, на сколько релизов мы отстали, и сравнивает с порогом.

Источник правды — core/upstream.toml. Локальным копиям апстрима не доверяем
принципиально: всё, что печатает этот скрипт, приходит из `git ls-remote`.

Запуск:
    python3 core/scripts/check-upstream-drift.py
    python3 core/scripts/check-upstream-drift.py --verbose
    python3 core/scripts/check-upstream-drift.py --json

Коды возврата:
    0  всё в пределах порогов
    1  отставание превышает max_lag хотя бы у одной позиции
    2  НЕ СОШЁЛСЯ ЭТАЛОН (тег не резолвится / коммит не совпал) — хуже, чем 1
    3  нет сети / git недоступен  (в CI трактуется как neutral, не как провал)
    4  реестр битый или отсутствует
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CORE = Path(__file__).resolve().parent.parent
REGISTRY = CORE / "upstream.toml"

LS_REMOTE_TIMEOUT = 25

EXIT_OK = 0
EXIT_LAG = 1
EXIT_REF_MISMATCH = 2
EXIT_NO_NETWORK = 3
EXIT_BAD_REGISTRY = 4


# --------------------------------------------------------------------------
# вывод
# --------------------------------------------------------------------------

_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


def red(s):
    return _c("31", s)


def green(s):
    return _c("32", s)


def yellow(s):
    return _c("33", s)


def bold(s):
    return _c("1", s)


def dim(s):
    return _c("2", s)


# --------------------------------------------------------------------------
# semver
# --------------------------------------------------------------------------

_NUM = re.compile(r"\d+")


def version_key(tag: str) -> tuple:
    """
    Грубый, но устойчивый ключ сортировки: все числа тега по порядку.

    Работает и для v1.13.14, и для v1.92.4-sing-box-1.13-mod.7,
    и для v0.4.6-extended-1.0.0. Нам не нужна полная semver-семантика —
    нужен стабильный порядок ВНУТРИ одного tag_filter, а фильтр по построению
    отбирает теги одной формы.
    """
    return tuple(int(n) for n in _NUM.findall(tag))


# --------------------------------------------------------------------------
# git
# --------------------------------------------------------------------------


class NetworkDown(Exception):
    pass


def ls_remote(url: str, *patterns: str, flags: tuple[str, ...] = ()) -> list[str]:
    # ВАЖНО: git ls-remote [flags] <url> [patterns...] — паттерны идут ПОСЛЕ url.
    # Если поставить их до, git примет первый паттерн за адрес репозитория и
    # вернёт «not found» на теги, которые на самом деле существуют.
    try:
        proc = subprocess.run(
            ["git", "ls-remote", *flags, url, *patterns],
            capture_output=True,
            text=True,
            timeout=LS_REMOTE_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        raise NetworkDown(f"git ls-remote timed out after {LS_REMOTE_TIMEOUT}s: {url}")
    except FileNotFoundError:
        raise NetworkDown("git не найден в PATH")

    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        tail = err[-1] if err else f"exit {proc.returncode}"
        low = tail.lower()
        if any(
            m in low
            for m in (
                "could not resolve host",
                "connection timed out",
                "network is unreachable",
                "connection refused",
                "temporary failure in name resolution",
                "failed to connect",
            )
        ):
            raise NetworkDown(f"{url}: {tail}")
        # Репозиторий отвечает, но не отдаёт то, что просили (нет прав,
        # переименован, удалён). Это НЕ отсутствие сети — это факт о записи.
        return []
    return [ln for ln in proc.stdout.splitlines() if ln.strip()]


def remote_tags(url: str, tag_filter: str | None) -> list[str]:
    lines = ls_remote(url, flags=("--tags",))
    pat = re.compile(tag_filter) if tag_filter else None
    tags = []
    for ln in lines:
        try:
            ref = ln.split("\t", 1)[1]
        except IndexError:
            continue
        if ref.endswith("^{}"):
            continue
        tag = ref.removeprefix("refs/tags/")
        if pat and not pat.match(tag):
            continue
        tags.append(tag)
    return sorted(set(tags), key=version_key)


def remote_tag_commit(url: str, tag: str) -> str | None:
    """Коммит, на который указывает тег. Аннотированный тег разыменовываем."""
    lines = ls_remote(url, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}")
    sha_plain = sha_peeled = None
    for ln in lines:
        sha, _, ref = ln.partition("\t")
        if ref.endswith("^{}"):
            sha_peeled = sha.strip()
        else:
            sha_plain = sha.strip()
    return sha_peeled or sha_plain


def remote_head(url: str) -> str | None:
    for ln in ls_remote(url, "HEAD"):
        return ln.split("\t", 1)[0].strip()
    return None


# --------------------------------------------------------------------------
# go.mod
# --------------------------------------------------------------------------

_REPLACE = re.compile(r"^\s*replace\s+(\S+)\s+=>\s+(\S+)(?:\s+(\S+))?\s*$")
_REQUIRE = re.compile(r"^\s*(\S+)\s+(v\S+)")


def gomod_version(gomod: Path, module: str) -> str | None:
    """
    Эффективная версия модуля по go.mod: replace имеет приоритет над require.

    Читаем ФАЙЛ, а не `go list -m`: скрипт обязан работать без сети и без
    прогретого модульного кеша. Побочный плюс — по этой оси реестр не может
    протухнуть: текущая версия всегда берётся живьём.
    """
    if not gomod.exists():
        return None
    replaced = None
    required = None
    in_block = False
    for raw in gomod.read_text(encoding="utf-8").splitlines():
        line = raw.split("//", 1)[0].rstrip()
        if not line.strip():
            continue

        m = _REPLACE.match(line)
        if m and m.group(1) == module:
            # `replace X => ./local` (без версии) — версии нет, дерево локальное.
            replaced = m.group(3)
            continue

        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line.startswith(")"):
            in_block = False
            continue

        cand = line[len("require "):] if line.startswith("require ") else (line if in_block else None)
        if cand:
            m = _REQUIRE.match(cand)
            if m and m.group(1) == module:
                required = m.group(2)

    return replaced or required


# --------------------------------------------------------------------------
# модель
# --------------------------------------------------------------------------


@dataclass
class Result:
    id: str
    kind: str
    upstream: str
    current: str = "?"
    latest: str = "?"
    lag: int | None = None
    max_lag: int = 3
    status: str = "ok"  # ok | lag | ref-mismatch | unknown | skipped
    notes: list[str] = field(default_factory=list)
    divergences: list[str] = field(default_factory=list)
    path: str = ""

    @property
    def failed_ref(self) -> bool:
        return self.status == "ref-mismatch"

    @property
    def failed_lag(self) -> bool:
        return self.status == "lag"


def verify_reference(entry: dict, res: Result) -> None:
    """
    Шаг 1 — САМЫЙ ВАЖНЫЙ. Доказать, что записанный эталон — это то, чем он себя
    называет. Без этого шага любое последующее сравнение кода бессмысленно.
    """
    ref = entry.get("ref")
    ref_commit = entry.get("ref_commit")
    if not ref:
        return

    if entry["kind"] == "commit":
        # У апстрима нет тегов — мерить «на сколько релизов отстали» не в чем.
        # Единственное, что тут проверяемо: совпадает ли пин с HEAD апстрима.
        if not ref_commit:
            res.status = "unknown"
            res.notes.append("нет ref_commit — эталон не зафиксирован вообще")
            return
        head = remote_head(entry["upstream"])
        if head is None:
            res.status = "unknown"
            res.notes.append(
                f"апстрим не отвечает на ls-remote HEAD — эталон {ref_commit[:12]} НЕ ПОДТВЕРЖДЁН. "
                f"Репозиторий мог быть переименован/удалён; тогда наша копия — единственная."
            )
            return
        if head.startswith(ref_commit):
            res.latest = "HEAD=" + head[:12]
            res.lag = 0
            res.notes.append(dim(f"пин == HEAD апстрима ({head[:12]})"))
        else:
            res.latest = "HEAD=" + head[:12]
            res.lag = None
            res.status = "unknown"
            res.notes.append(
                f"пин {ref_commit[:12]} != HEAD {head[:12]}: апстрим ушёл вперёд. "
                f"У репозитория нет тегов — «на сколько релизов» неизмеримо, нужен ручной обзор коммитов."
            )
        return

    actual = remote_tag_commit(entry["upstream"], ref)
    if actual is None:
        res.status = "ref-mismatch"
        res.notes.append(
            f"ЭТАЛОН НЕ РЕЗОЛВИТСЯ: тег {ref} у {entry['upstream']} не найден. "
            f"Не сравнивай код против него, пока не разберёшься."
        )
        return

    if ref_commit and not actual.startswith(ref_commit) and not ref_commit.startswith(actual):
        res.status = "ref-mismatch"
        res.notes.append(
            f"ЭТАЛОН СЪЕХАЛ: {ref} в реестре записан как {ref_commit[:12]}, "
            f"а апстрим сейчас отдаёт {actual[:12]}. Тег перетегирован ИЛИ в реестре не та версия."
        )
        return

    if ref_commit:
        res.notes.append(dim(f"эталон подтверждён: {ref} == {actual[:12]}"))


def check_entry(entry: dict, default_max_lag: int) -> Result:
    res = Result(
        id=entry["id"],
        kind=entry["kind"],
        upstream=entry["upstream"],
        max_lag=entry.get("max_lag", default_max_lag),
        divergences=list(entry.get("divergences", [])),
        path=entry.get("path", ""),
    )

    if res.kind == "module":
        cur = gomod_version(CORE / entry.get("gomod", "go.mod"), entry["module"])
        if cur is None:
            res.status = "unknown"
            res.notes.append(f"модуль {entry['module']} не найден в {entry.get('gomod', 'go.mod')}")
            return res
        res.current = cur
    else:
        res.current = entry.get("ref", "?")

    # --- шаг 1: верификация эталона ---
    verify_reference(entry, res)
    if res.failed_ref:
        return res
    if res.kind == "commit":
        # Отставание по тегам для commit-пинов не считается: их и нет.
        return res

    # --- шаг 2: отставание ---
    tags = remote_tags(entry["upstream"], entry.get("tag_filter"))
    if not tags:
        if res.status == "ok":
            res.status = "unknown"
        res.notes.append("апстрим не отдал ни одного тега под tag_filter (форк без релизов / нет доступа)")
        return res

    res.latest = tags[-1]
    cur_key = version_key(res.current)
    newer = [t for t in tags if version_key(t) > cur_key]
    res.lag = len(newer)

    if res.lag > res.max_lag:
        res.status = "lag"
    if newer:
        head = ", ".join(newer[:6]) + (" …" if len(newer) > 6 else "")
        res.notes.append(f"новее нас: {head}")
    if res.lag == 0 and version_key(res.current) > version_key(res.latest):
        res.notes.append("наш пин ВПЕРЕДИ старшего тега (псевдоверсия) — отставания нет")

    return res


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def render(results: list[Result], verbose: bool) -> None:
    w_id = max(12, max(len(r.id) for r in results))
    w_cur = max(9, max(len(str(r.current)) for r in results))
    w_lat = max(9, max(len(str(r.latest)) for r in results))

    print()
    print(bold("  InHive core — отставание от апстримов"))
    print(dim(f"  реестр: {REGISTRY}"))
    print(dim("  все версии получены из сети (git ls-remote), не из локальных копий"))
    print()
    print(
        f"  {'ПОЗИЦИЯ'.ljust(w_id)}  {'НАШЕ'.ljust(w_cur)}  {'АПСТРИМ'.ljust(w_lat)}  "
        f"{'ЛАГ':>5}  {'ПОРОГ':>5}  СТАТУС"
    )
    print("  " + "-" * (w_id + w_cur + w_lat + 32))

    for r in results:
        lag = "—" if r.lag is None else str(r.lag)
        if r.status == "ref-mismatch":
            mark = red("ЭТАЛОН СЪЕХАЛ")
        elif r.status == "lag":
            mark = red("ОТСТАЛИ")
        elif r.status == "unknown":
            mark = yellow("НЕ ПРОВЕРЕНО")
        elif r.lag:
            mark = yellow("в пределах порога")
        else:
            mark = green("ok")
        print(
            f"  {r.id.ljust(w_id)}  {str(r.current).ljust(w_cur)}  {str(r.latest).ljust(w_lat)}  "
            f"{lag:>5}  {r.max_lag:>5}  {mark}"
        )

    print()
    for r in results:
        interesting = r.status in ("lag", "ref-mismatch", "unknown") or verbose
        if not interesting:
            continue
        print(f"  {bold(r.id)}{dim('  ' + r.path if r.path else '')}")
        for n in r.notes:
            print(f"    · {n}")
        if verbose and r.divergences:
            print(dim("    наши намеренные расхождения:"))
            for d in r.divergences:
                print(dim(f"      - {d}"))
        print()


def main() -> int:
    ap = argparse.ArgumentParser(description="Сверка вендоренного кода InHive core с апстримами.")
    ap.add_argument("--verbose", "-v", action="store_true", help="показать намеренные расхождения по каждой позиции")
    ap.add_argument("--json", action="store_true", help="машиночитаемый вывод")
    ap.add_argument("--only", metavar="ID", help="проверить одну позицию")
    args = ap.parse_args()

    if not REGISTRY.exists():
        print(f"реестр не найден: {REGISTRY}", file=sys.stderr)
        return EXIT_BAD_REGISTRY
    if shutil.which("git") is None:
        print("git не найден в PATH — проверить апстримы нечем.", file=sys.stderr)
        return EXIT_NO_NETWORK

    try:
        with REGISTRY.open("rb") as fh:
            reg = tomllib.load(fh)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        print(f"реестр не читается: {exc}", file=sys.stderr)
        return EXIT_BAD_REGISTRY

    entries = reg.get("entry", [])
    if not entries:
        print("в реестре нет ни одной записи [[entry]].", file=sys.stderr)
        return EXIT_BAD_REGISTRY
    if args.only:
        entries = [e for e in entries if e["id"] == args.only]
        if not entries:
            print(f"позиция '{args.only}' в реестре не найдена.", file=sys.stderr)
            return EXIT_BAD_REGISTRY

    default_max_lag = reg.get("meta", {}).get("default_max_lag", 3)

    results: list[Result] = []
    for entry in entries:
        try:
            results.append(check_entry(entry, default_max_lag))
        except NetworkDown as exc:
            # Без сети смысла продолжать нет — но и падать stacktrace'ом нельзя.
            print()
            print(yellow("  Нет доступа к сети — проверка отставания не выполнена."))
            print(f"  {exc}")
            print()
            print("  Это НЕ значит, что всё в порядке: значит, что мы не знаем.")
            print("  Повтори при наличии сети. В CI такой прогон = neutral, не провал.")
            print()
            return EXIT_NO_NETWORK
        except KeyError as exc:
            print(f"битая запись реестра (нет поля {exc}): {entry.get('id', '?')}", file=sys.stderr)
            return EXIT_BAD_REGISTRY

    if args.json:
        print(json.dumps([r.__dict__ for r in results], ensure_ascii=False, indent=2, default=str))
    else:
        render(results, args.verbose)

    bad_ref = [r for r in results if r.failed_ref]
    lagging = [r for r in results if r.failed_lag]
    unknown = [r for r in results if r.status == "unknown"]

    if not args.json:
        if bad_ref:
            print(red(bold("  ЭТАЛОН НЕ СОШЁЛСЯ: " + ", ".join(r.id for r in bad_ref))))
            print("  Перед любым diff-аудитом против апстрима это надо закрыть:")
            print("  сравнение с неверной версией даёт не 'неточный', а ПРОТИВОПОЛОЖНЫЙ ответ")
            print("  (xmux 26.1.13 maxConcurrency 1..1 vs 26.7.11 maxConnections 6..6, 2026-07-19).")
            print()
        if lagging:
            print(red(bold("  ОТСТАЛИ СВЕРХ ПОРОГА: " + ", ".join(f"{r.id} (+{r.lag})" for r in lagging))))
            print("  Забирать апстрим ЦЕЛИКОМ, включая протоколы, которыми мы сами не пользуемся:")
            print("  InHive — универсальный клиент, ими пользуются юзеры на чужих подписках.")
            print()
        if unknown:
            print(yellow("  НЕ ПРОВЕРЕНО (нужны руки): " + ", ".join(r.id for r in unknown)))
            print()
        if not (bad_ref or lagging or unknown):
            print(green(bold("  Всё в пределах порогов.")))
            print()

    if bad_ref:
        return EXIT_REF_MISMATCH
    if lagging:
        return EXIT_LAG
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
