$ErrorActionPreference = "Continue"
Set-Location F:\Desktop\inhive\core
if (Test-Path bin\inhive-core.aar) { Remove-Item bin\inhive-core.aar -Force }
if (Test-Path build) { Remove-Item build -Recurse -Force -ErrorAction SilentlyContinue }
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "C:\Users\Marina\go\bin\gomobile.exe"
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.WorkingDirectory = "F:\Desktop\inhive\core"
# Version stamp (same -X as Makefile VERSION_LDFLAGS / build-dll-windows.ps1):
# without it the Android core reports 'unknown' in box.log and diagnostics.
# (v2/hcommon/constants.Version — вторая, инхайвовская версия — снесена
# 2026-09-24: 0 читателей после сноса CLI 2026-09-23; -X флаг снят здесь же.)
$version = (& git describe --tags 2>$null | Out-String).Trim()
if (-not $version) { $version = 'unknown' }
Write-Output "VERSION_STAMP=$version"
$bindArgs = @('bind','-v','-androidapi=24','-javapkg=com.inhive.core','-libname=inhive-core',
  '-tags=with_gvisor,with_quic,with_wireguard,with_utls,with_clash_api,with_grpc,with_awg,tfogo_checklinkname0,with_naive_outbound,with_olcrtc',
  '-trimpath',('-ldflags=-w -s -checklinkname=0 -buildid= ' +
    '-X github.com/sagernet/sing-box/constant.Version=' + $version + ' ' +
    '-X internal/godebug.defaultGODEBUG=multipathtcp=0'),
  '-target=android/arm,android/arm64,android/amd64',
  '-o','bin/inhive-core.aar',
  'github.com/sagernet/sing-box/experimental/libbox','./platform/mobile')
if ($psi.PSObject.Properties.Name -contains 'ArgumentList') {
  foreach ($a in $bindArgs) { $psi.ArgumentList.Add($a) }
} else {
  $psi.Arguments = ($bindArgs | ForEach-Object { '"' + $_ + '"' }) -join ' '
}
$psi.EnvironmentVariables.Clear()
foreach ($e in [Environment]::GetEnvironmentVariables().GetEnumerator()) {
  $k = [string]$e.Key
  if ($k.Length -gt 0 -and $k[0] -ne '=') { $psi.EnvironmentVariables[$k] = [string]$e.Value }
}
$psi.EnvironmentVariables["CGO_LDFLAGS"] = "-O2 -s -w -Wl,-z,max-page-size=16384"
# limit build parallelism — prevents Windows handle/memory exhaustion ("cannot open wait.h")
$psi.EnvironmentVariables["GOFLAGS"] = "-p=2"
$psi.EnvironmentVariables["GOMAXPROCS"] = "4"
$p = [System.Diagnostics.Process]::Start($psi)
$so = $p.StandardOutput.ReadToEndAsync()
$se = $p.StandardError.ReadToEndAsync()
$p.WaitForExit()
$log = "F:\Desktop\inhive\logs-4723\aar-full.log"
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
Set-Content -Path $log -Value ("=== bind exit=$($p.ExitCode) at $(Get-Date) ===`n" + $so.Result + "`n=== STDERR ===`n" + $se.Result) -Encoding utf8
Write-Output "=== bind exit=$($p.ExitCode) at $(Get-Date) ==="
if (Test-Path bin\inhive-core.aar) { Write-Output "AAR_SIZE=$((Get-Item bin\inhive-core.aar).Length) bytes" } else { Write-Output "AAR NOT created" }
