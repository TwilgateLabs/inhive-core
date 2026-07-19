<#
.SYNOPSIS
    Синхронизирует libcronet.dll (рантайм-библиотека naive) с пином из go.mod.

.DESCRIPTION
    ПОЧЕМУ ЭТОТ ШАГ СУЩЕСТВУЕТ ОТДЕЛЬНО ОТ `go build`.

    На Windows — и ТОЛЬКО на Windows — DLL собирается с тегом with_purego
    (core/Makefile: WINDOWS_ADD_TAGS=with_purego). Под этим тегом cronet НЕ
    линкуется в inhive-core.dll статически. Вместо этого cronet-go грузит
    библиотеку в РАНТАЙМЕ:
        internal/cronet/loader_windows.go -> findLibrary() ищет "libcronet.dll"
        рядом с .exe и по PATH, затем syscall.LoadLibrary + GetProcAddress
        по каждому Cronet_*-символу.

    Почему именно эти ОС:
      * Windows  — with_purego, динамическая загрузка => нужен отдельный файл.
      * Android  — cronet линкуется статически внутрь libinhive-core.so
                   (gomobile тянет android-слайс), пересборка AAR закрывает всё.
      * iOS/macOS — статический CGO-линк libcronet.a, см.
                   feedback_build_ios_cronet_purego.
    То есть ручной шаг нужен ровно на Windows, и поэтому его так легко забыть.

    ДВА СЛЕДСТВИЯ, ИЗ-ЗА КОТОРЫХ ЭТО ЛОВИТСЯ ТОЛЬКО У ПОЛЬЗОВАТЕЛЯ:
      1. `go build` никогда не падает из-за libcronet.dll — компилятор про него
         не знает. Сборка зелёная, артефакт битый.
      2. Отсутствие файла всплывает в NewNaiveClient -> checkLibrary
         (cronet-go/naive_client.go:97-100) как "cronet: library not found",
         т.е. при создании naive-outbound'а на машине пользователя.

    ХУЖЕ ОТСУТСТВИЯ — VERSION SKEW. Файл на месте, но собран под другую ревизию
    Chromium, чем Go-код. Символы резолвятся по имени, ABI разъезжается молча.
    Инцидент 2026-07-05 (релиз 4.7.0): Go-код Chromium 148, libcronet.dll в
    инсталляторе 143. Именно поэтому скрипт сверяет ВЕРСИИ, а Test-Path
    недостаточно.

    Источник истины — пин lib-слайса в go.mod, разрешаемый через `go list -m`.
    Никаких захардкоженных псевдоверсий: следующий бамп cronet-go подхватится
    сам.

.PARAMETER CoreDir
    Каталог core/. По умолчанию вычисляется от расположения скрипта.

.PARAMETER DestDir
    Куда положить libcronet.dll. По умолчанию app/inhive-core/bin — ровно тот
    путь, из которого CMake забирает файл в Release-бандл
    (app/windows/CMakeLists.txt:90).
#>
[CmdletBinding()]
param(
    [string]$CoreDir,
    [string]$DestDir
)

$ErrorActionPreference = "Stop"

if (-not $CoreDir) { $CoreDir = Split-Path -Parent $PSScriptRoot }
if (-not $DestDir)  { $DestDir = Join-Path (Split-Path -Parent $CoreDir) "app\inhive-core\bin" }

$slicePath = "github.com/sagernet/cronet-go/lib/windows_amd64"

# Регексп версии Chromium. libcronet.dll собран без version-resource, поэтому
# VersionInfo.FileVersion ПУСТ — версию видно только поиском по байтам.
$verPattern = '1[0-9]{2}\.0\.[0-9]{4}\.[0-9]+'

function Get-ChromiumVersion([string]$dllPath) {
    $bytes = [IO.File]::ReadAllBytes($dllPath)
    $text  = [Text.Encoding]::ASCII.GetString($bytes)
    $found = [regex]::Matches($text, $verPattern) |
             ForEach-Object { $_.Value } |
             Sort-Object -Unique
    if ($found.Count -eq 0) { return $null }
    return @($found)[0]
}

Push-Location $CoreDir
try {
    $sliceDir = (& go list -m -f '{{.Dir}}' $slicePath 2>$null | Select-Object -First 1)
    $pin      = (& go list -m -f '{{.Version}}' $slicePath 2>$null | Select-Object -First 1)

    if (-not $sliceDir) {
        throw "не удалось разрешить слайс $slicePath через go list. Прогрейте кэш: go mod download $slicePath"
    }

    $srcDll = Join-Path $sliceDir "libcronet.dll"
    if (-not (Test-Path $srcDll)) {
        throw "в слайсе нет libcronet.dll: $srcDll. Прогрейте кэш: go mod download $slicePath"
    }

    $srcVer = Get-ChromiumVersion $srcDll
    if (-not $srcVer) {
        throw "не удалось прочитать версию Chromium из $srcDll — формат libcronet.dll изменился?"
    }

    New-Item -ItemType Directory -Force -Path $DestDir | Out-Null
    $dstDll = Join-Path $DestDir "libcronet.dll"

    # Модульный кэш read-only; и сам источник, и уже лежащая копия могут иметь
    # выставленный IsReadOnly — Copy-Item на такую цель падает.
    if (Test-Path $dstDll) { Set-ItemProperty -Path $dstDll -Name IsReadOnly -Value $false }
    Copy-Item $srcDll $dstDll -Force
    Set-ItemProperty -Path $dstDll -Name IsReadOnly -Value $false

    $dstVer = Get-ChromiumVersion $dstDll
    if ($srcVer -ne $dstVer) {
        throw "version skew после копирования: слайс=$srcVer деплой=$dstVer"
    }

    Write-Output "OK libcronet.dll синхронизирован: Chromium $srcVer (пин $pin)"
    Write-Output "   -> $dstDll"
}
finally {
    Pop-Location
}

# InHive 2026-07-19: явный exit 0 обязателен.
# Вызывающий (build-dll-windows.ps1) проверяет $LASTEXITCODE после `& этот-скрипт`,
# но PowerShell выставляет $LASTEXITCODE только для NATIVE-команд. Без exit там
# оставалось значение от последнего внутреннего вызова `go list` (который пишет
# "go: downloading ..." в stderr и отдаёт ненулевой код), и сборка падала с
# "синхронизация провалилась (exit=-1)" СРАЗУ ПОСЛЕ строки "OK синхронизирован".
# При throw выше PowerShell сам выставит ненулевой код, так что проверка у
# вызывающего остаётся рабочей в обе стороны.
exit 0
