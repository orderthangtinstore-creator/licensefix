$ErrorActionPreference = 'Stop'
$source = [IO.File]::ReadAllText((Join-Path $PSScriptRoot '..\LicenseFix.ps1'), [Text.Encoding]::UTF8)
$marker = "if (-not `$env:SystemRoot) { throw 'Windows only.' }"
$index = $source.LastIndexOf($marker, [StringComparison]::Ordinal)
if ($index -lt 0) { throw 'Entry marker changed; refusing to run interactive script.' }
. ([scriptblock]::Create($source.Substring(0, $index)))

if ((LF-LicenseState 1) -notmatch 'Đã kích hoạt') { throw 'Wrong license status label.' }
if (-not (LF-IsVolumeProduct ([pscustomobject]@{ ProductKeyChannel='VOLUME_MAK'; Description='' }))) { throw 'Volume detection failed.' }
if (LF-IsVolumeProduct ([pscustomobject]@{ ProductKeyChannel='OEM:DM'; Description='' })) { throw 'OEM classified as Volume.' }
$emptyId = New-Object byte[] 67
if (LF-DecodeWindowsDigitalProductId $emptyId) { throw 'Empty registry value decoded as a real key.' }
$emptyId[52] = 1
if ((LF-DecodeWindowsDigitalProductId $emptyId) -cne 'BBBBB-BBBBB-BBBBB-BBBBB-BBBBC') {
    throw 'Legacy registry key decoding failed.'
}
$emptyId[52] = 0; $emptyId[66] = 8
if ((LF-DecodeWindowsDigitalProductId $emptyId) -cne 'NBBBB-BBBBB-BBBBB-BBBBB-BBBBB') {
    throw 'Windows 8+ registry key decoding failed.'
}
function LF-Admin { return $true }
$blockedWindows = [pscustomobject]@{ DomainJoinedOrUnknown=$true; WindowsVolume=$false; WindowsName='Test' }
if (LF-InstallWindowsKey $blockedWindows) { throw 'Domain Windows key guard failed.' }
$oldOfficeRecord = [pscustomobject]@{ OfficeVolume=$true; InstalledOfficeVolume=$false }
if (LF-InstallOfficeVolumeKey $oldOfficeRecord) { throw 'Stale Office WMI guard failed.' }

$sample = [pscustomobject]@{
    Base = [pscustomobject]@{
        Issues=@(); DomainJoinedOrUnknown=$true; WindowsLicensed=$true;
        OfficeSafe=$true; KmsVolume=$false
    }
    Items = @([pscustomobject]@{ Id=1; Name='Mục thử'; Status='REVIEW'; Action='Kiểm tra thủ công.' })
}
function LF-InspectHosts { return [pscustomobject]@{SafeLines=@(); ManualLines=@()} }
$plan = (LF-DeepPlan $sample 6>&1 | Out-String)
if ($plan -notmatch 'Khóa sửa' -or $plan -notmatch '19 nhóm là mục kiểm tra') {
    throw 'Repair plan did not explain unavailable actions.'
}
$script:answers = New-Object 'System.Collections.Generic.Queue[string]'
$script:answers.Enqueue('0')
function Read-Host { param([string]$Prompt) return $script:answers.Dequeue() }
$action = (LF-DeepAction $sample 6>&1 | Out-String)
if ($action -notmatch 'Đã hủy') { throw 'Repair action menu did not accept cancel.' }
$script:answers.Enqueue('')
$cancelledReveal = (LF-ShowFullWindowsKeys ([pscustomobject]@{Windows=@()}) 6>&1 | Out-String)
if ($cancelledReveal -notmatch 'Đã hủy') { throw 'Full key reveal did not require confirmation.' }

$script:planCalls = 0; $script:actionCalls = 0; $script:scanCalls = 0
$script:LFLastDeep = $null
function LF-DeepInspect { $script:scanCalls++; return $sample }
function LF-DeepPlan { param($Scan) $script:planCalls++; Write-Host 'PLAN' }
function LF-DeepAction { param($Scan) $script:actionCalls++; Write-Host 'ACTION' }
function Clear-Host {}
$script:answers.Enqueue('2'); $script:answers.Enqueue('')
$script:answers.Enqueue('3'); $script:answers.Enqueue('')
$script:answers.Enqueue('0')
$null = LF-Menu 6>&1
if ($script:scanCalls -ne 1 -or $script:planCalls -ne 1 -or $script:actionCalls -ne 1) {
    throw "Main menu routes failed: scan=$script:scanCalls plan=$script:planCalls action=$script:actionCalls"
}
if ($script:answers.Count -ne 0) { throw 'Main menu left unconsumed input.' }
$script:refreshCalls = 0; $script:inventoryDisplays = 0
function LF-GetKeyInventory { param([switch]$ForceRefresh) $script:refreshCalls++; return [pscustomobject]@{ Revision=$script:refreshCalls } }
function LF-ShowKeyInventory { param($Inventory) $script:inventoryDisplays++; Write-Host ("Inventory revision $($Inventory.Revision)") }
function Read-Host {
    param([string]$Prompt)
    if ($Prompt -eq 'Nhấn Enter để tiếp tục' -and $script:inventoryDisplays -lt 2) {
        throw 'Refresh returned to prompt before displaying new inventory.'
    }
    return $script:answers.Dequeue()
}
$script:answers.Enqueue('1'); $script:answers.Enqueue(''); $script:answers.Enqueue('0')
$null = LF-KeyMenu 6>&1
if ($script:refreshCalls -ne 2 -or $script:inventoryDisplays -lt 2 -or $script:answers.Count -ne 0) {
    throw 'Key inventory refresh route failed.'
}
$fixtureId = New-Object byte[] 67
$fixtureId[52] = 1
function Get-CimInstance { return [pscustomobject]@{OA3xOriginalProductKey='AAAAA-BBBBB-CCCCC-DDDDD-EEEEE'} }
function Get-ItemProperty { return [pscustomobject]@{DigitalProductId=$fixtureId} }
$script:answers.Enqueue('HIENTHI')
$revealed = (LF-ShowFullWindowsKeys ([pscustomobject]@{
    Windows=@([pscustomobject]@{PartialProductKey='BBBBC'})
}) 6>&1 | Out-String)
if ($revealed -notmatch 'AAAAA-BBBBB-CCCCC-DDDDD-EEEEE' -or
    $revealed -notmatch 'BBBBB-BBBBB-BBBBB-BBBBB-BBBBC') {
    throw 'Confirmed full-key reveal failed for synthetic data.'
}
Write-Host 'Menu, refresh, and key classification regression checks passed.'
