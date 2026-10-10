# LicenseFix v2.1.2-beta - verified online launcher (PowerShell 5.1+, Windows only)
# Keep this launcher ASCII without a BOM for Invoke-RestMethod | Invoke-Expression.
# Usage:
# irm https://raw.githubusercontent.com/orderthangtinstore-creator/licensefix/main/launch.ps1 | iex
# This is independent of license.info.vn and does not modify Windows until user confirms inside LicenseFix.

$ErrorActionPreference = 'Stop'
$lfVersion = '2.1.2-beta'
# Pin the core to its release commit so GitHub CDN cannot mix launcher and core versions.
$lfSource = 'https://raw.githubusercontent.com/orderthangtinstore-creator/licensefix/39c0aa813a9ef1de80608076a79eef196e594826/LicenseFix.ps1'
$lfExpectedSHA256 = '9FD3A207534FFDCB9B83E40B910C9377CD4C57911EDFB95ABA927DCF95F331D9'

try {
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw 'Windows PowerShell 5.1 or later is required.'
    }
    if (-not $env:WINDIR -or -not $env:LOCALAPPDATA) {
        throw 'Windows is required.'
    }
    if (-not $lfSource.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing non-HTTPS source.'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $lfCacheDir = Join-Path $env:LOCALAPPDATA ('LicenseFix\OnlineCache\' + $lfVersion)
    $null = New-Item -Path $lfCacheDir -ItemType Directory -Force
    $lfDownload = Join-Path $lfCacheDir 'LicenseFix.download.ps1'
    $lfSaved = Join-Path $lfCacheDir 'LicenseFix.verified.ps1'
    Write-Host ('[LicenseFix] Downloading version ' + $lfVersion) -ForegroundColor Cyan
    Invoke-WebRequest -Uri $lfSource -OutFile $lfDownload -UseBasicParsing -MaximumRedirection 4 -TimeoutSec 30 -ErrorAction Stop | Out-Null
    $lfBytes = [IO.File]::ReadAllBytes($lfDownload)
    $lfSha = [Security.Cryptography.SHA256]::Create()
    try {
        $lfActual = [BitConverter]::ToString($lfSha.ComputeHash($lfBytes)).Replace('-', '').ToUpperInvariant()
    } finally { $lfSha.Dispose() }
    if ($lfActual -cne $lfExpectedSHA256) {
        Remove-Item -LiteralPath $lfDownload -Force -ErrorAction SilentlyContinue
        throw ('SHA256 mismatch. Expected ' + $lfExpectedSHA256 + ' / Got ' + $lfActual + '. No code executed. Please check release files.')
    }
    [IO.File]::WriteAllBytes($lfSaved, $lfBytes)
    Remove-Item -LiteralPath $lfDownload -Force -ErrorAction SilentlyContinue
    Write-Host ('[LicenseFix] Verified SHA-256: ' + $lfActual) -ForegroundColor Green
    Write-Host ('[LicenseFix] Verified copy: ' + $lfSaved) -ForegroundColor DarkGray
    $lfIsAdmin = $false
    try {
        $lfPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $lfIsAdmin = $lfPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}
    if (-not $lfIsAdmin) {
        Write-Warning '[LicenseFix] Administrator rights are required for repairs; scanning is available.'
    }
    # Execute only verified source. Never re-download on elevation; do not change execution policy.
    $lfCode = [Text.Encoding]::UTF8.GetString($lfBytes).TrimStart([char]0xFEFF)
    & ([ScriptBlock]::Create($lfCode)) -Mode Menu
} catch {
    Write-Host ('[LicenseFix] Launch stopped: ' + $_.Exception.Message) -ForegroundColor Red
    throw
}
