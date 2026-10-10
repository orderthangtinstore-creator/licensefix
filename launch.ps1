# LicenseFix v2.0.1-beta - verified online launcher (PowerShell 5.1+, Windows only)
# Usage:
# irm https://raw.githubusercontent.com/orderthangtinstore-creator/licensefix/main/launch.ps1 | iex
# This is independent of license.info.vn and does not modify Windows until user confirms inside LicenseFix.

$ErrorActionPreference = 'Stop'
$lfVersion = '2.0.1-beta'
$lfSource = 'https://raw.githubusercontent.com/orderthangtinstore-creator/licensefix/main/LicenseFix.ps1'
$lfExpectedSHA256 = '828E6FF99616F9C558C8A754439ACD64667B9FB7E0B1B48FFE6AED27E73C2B5E'

try {
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        throw 'Yêu cầu Windows PowerShell 5.1 trở lên.'
    }
    if (-not $env:WINDIR -or -not $env:LOCALAPPDATA) {
        throw 'Chỉ hỗ trợ Windows.'
    }
    if (-not $lfSource.StartsWith('https://', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing non-HTTPS source.'
    }
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $lfCacheDir = Join-Path $env:LOCALAPPDATA ('LicenseFix\OnlineCache\' + $lfVersion)
    $null = New-Item -Path $lfCacheDir -ItemType Directory -Force
    $lfDownload = Join-Path $lfCacheDir 'LicenseFix.download.ps1'
    $lfSaved = Join-Path $lfCacheDir 'LicenseFix.verified.ps1'
    Write-Host ('[LicenseFix] Đang tải phiên bản ' + $lfVersion) -ForegroundColor Cyan
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
    Write-Host ('[LicenseFix] Đã xác minh SHA-256: ' + $lfActual) -ForegroundColor Green
    Write-Host ('[LicenseFix] Bản sao đã xác minh: ' + $lfSaved) -ForegroundColor DarkGray
    $lfIsAdmin = $false
    try {
        $lfPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        $lfIsAdmin = $lfPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {}
    if (-not $lfIsAdmin) {
        Write-Warning '[LicenseFix] Chưa có quyền quản trị. Có thể quét; sửa lỗi cần chạy PowerShell với quyền Administrator.'
    }
    # Execute only verified source. Never re-download on elevation; do not change execution policy.
    $lfCode = [Text.Encoding]::UTF8.GetString($lfBytes).TrimStart([char]0xFEFF)
    & ([ScriptBlock]::Create($lfCode)) -Mode Menu
} catch {
    Write-Host ('[LicenseFix] Đã dừng khởi chạy: ' + $_.Exception.Message) -ForegroundColor Red
    throw
}
