<#
.SYNOPSIS
    Деплой inhive-core.aar в app/android/app/libs с проверкой 3 ABI и SHA256.

.DESCRIPTION
    PowerShell-эквивалент цели `android-deploy` из core/Makefile.

    ПОЧЕМУ ДУБЛЬ, А НЕ ПРОСТО `make android-deploy`:
    Makefile:10-12 отказывается запускаться под Windows_NT, а его рецепты
    построены на unzip/sha256sum/wc — их на голой Windows нет. Поэтому на
    Windows-сборщике гейт физически не мог отработать, и деплой сводился к
    голому Copy-Item. Этот скрипт восстанавливает те же три проверки на
    штатных средствах .NET (System.IO.Compression + Get-FileHash).

    ЧТО ЛОВИТ. Локальная итерация соблазняет собрать один ABI
    (`gomobile bind -target=android/amd64`, 5-10 мин вместо 30 — например под
    LDPlayer). Если такой AAR попадёт в деплой-путь, APK соберётся зелёным, но
    без arm-библиотек: КАЖДЫЙ тестер на реальном телефоне получит
    UnsatisfiedLinkError. Сборка при этом не падает — ломается только у
    пользователя. Инциденты: Phase 1 Universal APK (2026-04-24) и повтор
    2026-04-25, когда памятка уже существовала и не помогла — поэтому проверка
    исполняемая, а не в документации.

    Проверки:
      1. В исходном AAR ровно 3 ABI (arm64-v8a + armeabi-v7a + x86_64).
      2. SHA256 источника совпадает с задеплоенным (копия не побилась).
      3. В задеплоенном AAR тоже ровно 3 ABI.
    Порядок важен: не копировать, пока источник не признан валидным, иначе
    битый артефакт перезапишет хороший.
#>
[CmdletBinding()]
param(
    [string]$SourceAar,
    [string]$DestAar
)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.IO.Compression.FileSystem

$coreDir = Split-Path -Parent $PSScriptRoot
$repoDir = Split-Path -Parent $coreDir

if (-not $SourceAar) { $SourceAar = Join-Path $coreDir "bin\inhive-core.aar" }
if (-not $DestAar)   { $DestAar   = Join-Path $repoDir "app\android\app\libs\inhive-core.aar" }

$expectedAbis = @('arm64-v8a', 'armeabi-v7a', 'x86_64')

function Get-AarAbis([string]$aarPath) {
    $zip = [System.IO.Compression.ZipFile]::OpenRead($aarPath)
    try {
        return @($zip.Entries |
            Where-Object { $_.FullName -match '^jni/([^/]+)/libinhive-core\.so$' } |
            ForEach-Object { [regex]::Match($_.FullName, '^jni/([^/]+)/').Groups[1].Value } |
            Sort-Object -Unique)
    }
    finally {
        $zip.Dispose()
    }
}

if (-not (Test-Path $SourceAar)) {
    throw "не найден $SourceAar — сначала соберите AAR"
}

# --- 1. ABI в источнике -------------------------------------------------------
$srcAbis = Get-AarAbis $SourceAar
if ($srcAbis.Count -ne 3 -or (Compare-Object $srcAbis $expectedAbis)) {
    Write-Output "ABI в исходном AAR: $($srcAbis -join ', ')"
    throw "исходный AAR содержит $($srcAbis.Count) ABI, ожидается 3 ($($expectedAbis -join ' + ')). Деплой отменён."
}

# --- 2. Копирование + SHA256 --------------------------------------------------
$destDir = Split-Path -Parent $DestAar
New-Item -ItemType Directory -Force -Path $destDir | Out-Null
Copy-Item $SourceAar $DestAar -Force

$srcHash = (Get-FileHash $SourceAar -Algorithm SHA256).Hash
$dstHash = (Get-FileHash $DestAar   -Algorithm SHA256).Hash
if ($srcHash -ne $dstHash) {
    throw "SHA256 не совпал после копирования: источник=$srcHash деплой=$dstHash"
}

# --- 3. ABI в задеплоенном ----------------------------------------------------
$dstAbis = Get-AarAbis $DestAar
if ($dstAbis.Count -ne 3 -or (Compare-Object $dstAbis $expectedAbis)) {
    throw "задеплоенный AAR содержит $($dstAbis.Count) ABI после копирования — проблема с ФС?"
}

$sizeMB = [math]::Round((Get-Item $DestAar).Length / 1MB, 1)
Write-Output "OK AAR задеплоен: 3 ABI ($($dstAbis -join ', ')), SHA256 совпал, ${sizeMB}MB"
Write-Output "   -> $DestAar"
