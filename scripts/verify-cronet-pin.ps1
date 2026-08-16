# verify-cronet-pin.ps1 - ловит libcronet.dll, разошедшийся с пином в go.mod.
#
# ЗАЧЕМ (инцидент 2026-07-05, релиз 4.7.0)
# ----------------------------------------
# Обновили cronet-go до Chromium 148, DLL пересобрали - а Windows-инсталлятор
# унёс libcronet.dll версии 143.0.7499.109. Go-код ждал ABI 148, purego грузил
# 143. Сборка при этом ЗЕЛЁНАЯ и остаётся зелёной: компилятор про libcronet.dll
# не знает вообще (на десктопе cronet НЕ линкуется статически, грузится в
# рантайме через purego), поэтому ломается только у пользователя - naive просто
# не работает. Ровно feedback_meta_unreportable_bug_class.
#
# Почему одного sync-naive-lib-windows.ps1 мало: он КОПИРУЕТ dll из слайса, но
# ничего не проверяет ПОСЛЕ сборки. Голый `go build` мимо обёртки, ручная
# правка, недокопированный файл, переставленный Release - всё это проходит
# молча. Этот скрипт проверяет то, что реально уедет пользователю.
#
# ИСТОЧНИК ИСТИНЫ - не захардкоженный номер версии, а САМ СЛАЙС из пина go.mod.
# Поэтому при следующем бампе cronet скрипт править не надо: эталон поедет сам.
#
# Использование:
#   powershell -File core/scripts/verify-cronet-pin.ps1
#   powershell -File core/scripts/verify-cronet-pin.ps1 -Paths "F:\...\Release\libcronet.dll"
# Exit 0 - совпало; 1 - рассинхрон или файл не найден; 2 - не смог разрешить эталон.

param(
    # Что проверять. По умолчанию - канонический источник для CMake и, если есть,
    # собранная Release-папка (именно её содержимое попадает в инсталлятор).
    [string[]]$Paths
)

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$core = Split-Path -Parent $here
$repo = Split-Path -Parent $core
$app  = Join-Path $repo 'app'

# libcronet.dll собран без version-resource, поэтому FileVersion ПУСТ и
# Get-Item .VersionInfo бесполезен - версию видно только строками в байтах.
function Get-ChromiumVersion([string]$dll) {
    if (-not (Test-Path $dll)) { return $null }
    $bytes = [IO.File]::ReadAllBytes($dll)
    $txt   = [Text.Encoding]::ASCII.GetString($bytes)
    $m     = [regex]::Matches($txt, '\b1[0-9]{2}\.0\.[0-9]{4}\.[0-9]+\b')
    if ($m.Count -eq 0) { return $null }
    # Самая частая строка - это и есть версия сборки Chromium.
    ($m | ForEach-Object { $_.Value } | Group-Object | Sort-Object Count -Descending |
        Select-Object -First 1).Name
}

# ---- эталон: слайс из пина go.mod ----
Push-Location $core
$slice   = 'github.com/sagernet/cronet-go/lib/windows_amd64'
$pin     = (& go list -m -f '{{.Version}}' $slice 2>$null | Select-Object -First 1)
$sliceDir= (& go list -m -f '{{.Dir}}'     $slice 2>$null | Select-Object -First 1)
Pop-Location

if (-not $sliceDir) {
    Write-Output "verify-cronet-pin: cannot resolve $slice via go list."
    Write-Output "  warm the cache: cd core && go mod download $slice"
    exit 2
}
$expected = Get-ChromiumVersion (Join-Path $sliceDir 'libcronet.dll')
if (-not $expected) {
    Write-Output "verify-cronet-pin: no readable Chromium version in the slice ($sliceDir)"
    exit 2
}

Write-Output "libcronet.dll against the go.mod pin"
Write-Output ("  pin      : " + $pin)
Write-Output ("  expected : Chromium " + $expected)
Write-Output ""

if (-not $Paths -or $Paths.Count -eq 0) {
    $Paths = @(
        (Join-Path $app 'inhive-core\bin\libcronet.dll'),
        (Join-Path $app 'build\windows\x64\runner\Release\libcronet.dll')
    )
}

$checked = 0
$bad     = 0
foreach ($p in $Paths) {
    if (-not (Test-Path $p)) {
        Write-Output ("  -  " + $p + "  MISSING (skipped)")
        continue
    }
    $checked++
    $got = Get-ChromiumVersion $p
    if (-not $got) {
        Write-Output ("  X  " + $p + "  could not read a version")
        $bad++
    } elseif ($got -ne $expected) {
        Write-Output ("  X  " + $p)
        Write-Output ("      has Chromium " + $got + " but the Go code was built against " + $expected)
        $bad++
    } else {
        Write-Output ("  OK " + $p + "  Chromium " + $got)
    }
}

Write-Output ""
if ($checked -eq 0) {
    Write-Output "GATE FAILED: no libcronet.dll found anywhere - nothing was verified."
    Write-Output "A desktop build without it means naive is dead for the user."
    exit 1
}
if ($bad -gt 0) {
    Write-Output "GATE FAILED: libcronet.dll has drifted from the go.mod pin."
    Write-Output "The build stays GREEN (the compiler knows nothing about this dll) and naive"
    Write-Output "breaks only on the user machine - exactly like release 4.7.0."
    Write-Output "Fix: powershell -File core/scripts/sync-naive-lib-windows.ps1"
    exit 1
}
Write-Output "GATE PASSED."
exit 0
