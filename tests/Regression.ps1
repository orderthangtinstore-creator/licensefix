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
$script:systemCalls = 0
function LF-DeepSystem { param([string]$Tool) if($Tool -ne 'SFC'){throw 'Wrong repair tool'}; $script:systemCalls++; return $false }
$script:answers.Enqueue('S')
$null = LF-DeepAction $sample 6>&1
if ($script:systemCalls -ne 1) { throw 'SFC action was not routed to its command handler.' }
$script:answers.Enqueue('R')
$noFix = (LF-DeepAction $sample 6>&1 | Out-String)
if ($noFix -notmatch 'Chưa cần sao lưu' -or $noFix -notmatch 'Lý do khóa') {
    throw 'No-op Registry action did not explain why it skipped repair.'
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('LicenseFix-Regression-' + [guid]::NewGuid().ToString('N'))
$LFBackups = Join-Path $testRoot 'Backups'
[void](New-Item -ItemType Directory -Path $LFBackups -Force)
try {
    $regScan = [pscustomobject]@{
        RepairEligible=$true; DomainJoinedOrUnknown=$false; WindowsLicensed=$true;
        OfficeSafe=$true; KmsVolume=$false;
        Issues=@([pscustomobject]@{
            Id='KMS-001'; CanFix=$true; RegistryPath='HKLM:\SOFTWARE\LicenseFixRegression';
            ValueName='KeyManagementServiceName'; ExpectedValue='localhost'
        })
    }
    $script:repairEvents = New-Object 'System.Collections.Generic.List[string]'
    function LF-ExportRegistryKey {
        param([string]$NativePath,[string]$Destination)
        [void]$script:repairEvents.Add('backup')
        [IO.File]::WriteAllText($Destination, 'Windows Registry Editor Version 5.00')
    }
    function LF-ReadValue { return 'localhost' }
    function Remove-ItemProperty {
        param($LiteralPath,$Name,$ErrorAction)
        [void]$script:repairEvents.Add('remove')
    }
    $script:answers.Enqueue('N')
    $null = LF-Repair $regScan -SkipRescan 6>&1
    if ($script:repairEvents.Count -ne 0) { throw 'Registry repair changed data after declining confirmation.' }
    $script:answers.Enqueue('Y')
    $null = LF-Repair $regScan -SkipRescan 6>&1
    if (($script:repairEvents -join ',') -cne 'backup,remove' -or -not $script:LFRepairChanged) {
        throw 'Registry repair did not back up before removing the value.'
    }
    $script:repairEvents.Clear()
    function LF-ExportRegistryKey {
        param([string]$NativePath,[string]$Destination)
        [void]$script:repairEvents.Add('backup-failed')
        throw 'Synthetic backup failure'
    }
    $script:answers.Enqueue('Y')
    $backupFailure = (LF-Repair $regScan -SkipRescan 3>&1 6>&1 | Out-String)
    if (($script:repairEvents -join ',') -cne 'backup-failed' -or $script:LFRepairChanged -or
        $backupFailure -notmatch 'chưa sao lưu đầy đủ') {
        throw 'Registry repair did not stop and explain backup failure.'
    }

    $hostsFile = Join-Path $testRoot 'hosts.fixture'
    $originalHosts = [Text.Encoding]::ASCII.GetBytes("127.0.0.1 activation-v2.sls.microsoft.com`r`n")
    $fixedHosts = [Text.Encoding]::ASCII.GetBytes('')
    [IO.File]::WriteAllBytes($hostsFile, $originalHosts)
    $script:hostsReview = [pscustomobject]@{
        Path=$hostsFile; Bytes=$originalHosts; FixedBytes=$fixedHosts;
        SafeLines=@('127.0.0.1 activation-v2.sls.microsoft.com'); ManualLines=@()
    }
    function LF-InspectHosts { return $script:hostsReview }
    $hostsScan = [pscustomobject]@{ Base=[pscustomobject]@{ DomainJoinedOrUnknown=$false } }
    $script:answers.Enqueue('N')
    if (LF-RepairHosts $hostsScan) { throw 'Hosts repair ignored declined confirmation.' }
    if (-not [IO.File]::ReadAllBytes($hostsFile).Length) { throw 'Hosts changed after declined confirmation.' }
    $script:answers.Enqueue('Y')
    if (-not (LF-RepairHosts $hostsScan)) { throw 'Hosts repair failed on synthetic fixture.' }
    if ([IO.File]::ReadAllBytes($hostsFile).Length -ne 0) { throw 'Hosts fixture was not updated.' }
    $hostsBackups = @(Get-ChildItem -LiteralPath $LFBackups -Filter 'hosts-*' -Directory)
    if ($hostsBackups.Count -ne 1 -or
        ([IO.File]::ReadAllBytes((Join-Path $hostsBackups[0].FullName 'hosts.before')) -join ',') -cne ($originalHosts -join ',')) {
        throw 'Hosts original was not backed up before repair.'
    }
    [IO.File]::WriteAllBytes($hostsFile, $originalHosts)
    $LFBackups = Join-Path $testRoot 'backup-blocker'
    [IO.File]::WriteAllText($LFBackups, 'not a directory')
    $script:answers.Enqueue('Y')
    $hostsBackupFailure = (LF-RepairHosts $hostsScan 3>&1 6>&1 | Out-String)
    if ($hostsBackupFailure -notmatch 'chưa sao lưu và xác minh' -or
        ([IO.File]::ReadAllBytes($hostsFile) -join ',') -cne ($originalHosts -join ',')) {
        throw 'Hosts repair did not stop before writing when backup failed.'
    }
} finally {
    $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
    $expectedPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if (-not $resolvedTestRoot.StartsWith($expectedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
        -not ([IO.Path]::GetFileName($resolvedTestRoot)).StartsWith('LicenseFix-Regression-', [StringComparison]::Ordinal)) {
        throw 'Refusing to remove a test directory outside the named temporary area.'
    }
    Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
}
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
$script:planCalls=0; $script:actionCalls=0; $script:detailCalls=0
function LF-DeepInspect { $script:LFLastDeep=$sample; return $sample }
function LF-DeepDisplay { param($Scan) Write-Host 'SCAN RESULT' }
function LF-DeepDetail { param($Scan,[int]$Id) if($Id -ne 6){throw 'Wrong detail ID'}; $script:detailCalls++ }
$script:answers.Enqueue('1')
$script:answers.Enqueue('2'); $script:answers.Enqueue('6')
$script:answers.Enqueue('3'); $script:answers.Enqueue('4')
$script:answers.Enqueue('0'); $script:answers.Enqueue('0')
$null = LF-DeepMenu 6>&1
if ($script:detailCalls -ne 1 -or $script:planCalls -ne 1 -or
    $script:actionCalls -ne 1 -or $script:answers.Count -ne 0) {
    throw 'Deep scan result did not route directly to detail, plan, and repair actions.'
}
Write-Host 'Menu, scan follow-up, guarded backup/repair, refresh, and key regression checks passed.'
