<#
.SYNOPSIS
    Канонический билд inhive-core.dll под Windows.

.DESCRIPTION
    ПОЧЕМУ ЭТОТ СКРИПТ ВООБЩЕ НУЖЕН, РАЗ ЕСТЬ Makefile.

    core/Makefile:10-12 явно отказывается работать под Windows_NT ("use bash in
    WSL"), а нативная сборка DLL идёт на Windows-машине. Из-за этого шаги,
    записанные в Makefile, физически не исполнялись на сборщике, и каждый
    ad-hoc ps1 переписывал команду `go build` заново — теряя по дороге то
    синхронизацию libcronet.dll, то -X версии. Этот скрипт — единственная точка,
    через которую собирается Windows-DLL; всё остальное (build-task.ps1,
    диагностические сборки) обязано звать его, а не собственный `go build`.

    ЧТО ОН ГАРАНТИРУЕТ (каждый пункт — ранее забывавшийся шаг):
      1. Теги читаются ИЗ Makefile (BASE_TAGS + WINDOWS_ADD_TAGS), а не
         дублируются строкой. Makefile остаётся источником истины, дрейф
         невозможен по конструкции.
      2. libcronet.dll синхронизируется ДО сборки и билд падает, если это не
         удалось. См. sync-naive-lib-windows.ps1 — без него naive ломается
         только у пользователя.
      3. Проставляются -X constant.Version и -X godebug multipathtcp=0.
         Без первого бинарь рапортует "unknown" и молчит про deprecated-опции;
         без второго наш форк расходится поведением с апстримом.
      4. Артефакт проверяется на свежесть и размер, потом кладётся в
         app/inhive-core/bin — путь, который реально читает CMake.

.PARAMETER Configuration
    Release (по умолчанию) или Debug. В Debug не отдаются -w -s, чтобы
    сохранить символы для отладки.

.PARAMETER SkipNaiveLib
    Пропустить синхронизацию libcronet.dll. ТОЛЬКО для быстрой итерации, когда
    naive заведомо не используется. Для релизного артефакта — никогда.
#>
[CmdletBinding()]
param(
    [ValidateSet("Release", "Debug")]
    [string]$Configuration = "Release",
    [switch]$SkipNaiveLib
)

$ErrorActionPreference = "Stop"

$coreDir = Split-Path -Parent $PSScriptRoot
$repoDir = Split-Path -Parent $coreDir
$appCoreBin = Join-Path $repoDir "app\inhive-core\bin"
$outDll = Join-Path $coreDir "bin\inhive-core.dll"

# ---- 1. Теги из Makefile (единственный источник истины) ----------------------
$makefile = Join-Path $coreDir "Makefile"
if (-not (Test-Path $makefile)) { throw "не найден $makefile" }
$mk = Get-Content $makefile -Raw

function Get-MakeVar([string]$name) {
    $m = [regex]::Match($mk, "(?m)^$name=(.+?)\s*$")
    if (-not $m.Success) { throw "в Makefile не найдена переменная $name" }
    return $m.Groups[1].Value.Trim()
}

$baseTags = Get-MakeVar "BASE_TAGS"
$winTags  = Get-MakeVar "WINDOWS_ADD_TAGS"
$tags     = "$baseTags,$winTags"
Write-Output "теги из Makefile: $tags"

# ---- 2. libcronet.dll ДО сборки ---------------------------------------------
# Порядок важен: если синхронизация упадёт, мы не потратим 10 минут на go build
# и не оставим в деплой-пути свежий inhive-core.dll рядом со старым libcronet.
if ($SkipNaiveLib) {
    Write-Warning "SkipNaiveLib: libcronet.dll НЕ синхронизирован. Артефакт непригоден для релиза."
} else {
    & (Join-Path $PSScriptRoot "sync-naive-lib-windows.ps1") -CoreDir $coreDir -DestDir $appCoreBin
    if ($LASTEXITCODE -ne 0) { throw "синхронизация libcronet.dll провалилась (exit=$LASTEXITCODE)" }
}

# ---- 3. ldflags --------------------------------------------------------------
$version = (& git -C $coreDir describe --tags 2>$null | Select-Object -First 1)
if (-not $version) { $version = "unknown" }

# -checklinkname=0 обязателен для форка (см. tfogo_checklinkname0 в тегах).
# Версий две и обе объявлены "unknown": апстримная sing-box/constant.Version
# (её отдаёт clashapi и libbox) и наша v2/hcommon/constants.Version (её печатает
# `InhiveCli version`). Проставляются обе — иначе диагностика врёт в одном из
# двух мест, куда смотрят при разборе инцидента.
$ldflags = "-checklinkname=0 -buildid= " +
           "-X github.com/sagernet/sing-box/constant.Version=$version " +
           "-X github.com/twilgate/inhive-core/v2/hcommon/constants.Version=$version " +
           "-X internal/godebug.defaultGODEBUG=multipathtcp=0"
if ($Configuration -eq "Release") { $ldflags = "-w -s " + $ldflags }

Write-Output "версия в бинаре: $version ($Configuration)"

# ---- 4. Сборка ---------------------------------------------------------------
$buildStart = Get-Date
if (Test-Path $outDll) { Remove-Item $outDll -Force }

Push-Location $coreDir
try {
    $env:CGO_ENABLED = "1"
    & go build -trimpath -ldflags="$ldflags" -buildmode=c-shared -tags "$tags" -o "bin\inhive-core.dll" ".\platform\desktop"
    if ($LASTEXITCODE -ne 0) { throw "go build упал (exit=$LASTEXITCODE)" }
}
finally {
    Pop-Location
}

# ---- 5. Проверки артефакта ---------------------------------------------------
if (-not (Test-Path $outDll)) { throw "go build отработал, но $outDll не создан" }
$dll = Get-Item $outDll
if ($dll.LastWriteTime -lt $buildStart) { throw "DLL старее старта сборки — подхватился stale-артефакт" }
if ($dll.Length -lt 40MB) { throw ("DLL подозрительно мала: " + [math]::Round($dll.Length/1MB,1) + "MB (ожидается >40MB)") }

New-Item -ItemType Directory -Force -Path $appCoreBin | Out-Null
Copy-Item $outDll (Join-Path $appCoreBin "inhive-core.dll") -Force

Write-Output ("OK DLL " + [math]::Round($dll.Length/1MB,1) + "MB -> $appCoreBin\inhive-core.dll")

# InHive 2026-07-19: явный exit 0 — parity с sync-naive-lib-windows.ps1.
# PowerShell выставляет $LASTEXITCODE только для NATIVE-команд, поэтому при
# вызове этого скрипта через `& build-dll-windows.ps1` из обёртки или CI-шага
# вызывающий увидел бы код от последней внутренней нативной команды (go/git),
# а не результат сборки. Ровно на этом сегодня падал вызов sync-скрипта:
# "провалилась (exit=-1)" печаталось СРАЗУ ПОСЛЕ "OK синхронизирован".
# При throw выше PowerShell сам выставит ненулевой код.
exit 0
