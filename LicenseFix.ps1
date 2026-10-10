#requires -Version 5.1
<#
LicenseFix v1.2.0-preview - Windows/Office license diagnostics and scoped remediation.
Preview build: test on a lab PC before performing repairs.
Independent project. Not affiliated with Microsoft or license.info.vn.
Repairs only specifically reviewed Registry values after successful backups.
Never edits SPP data.dat/tokens.dat, license keys, history, or timestamps.
#>
[CmdletBinding()]
param([ValidateSet('Menu','Scan','Plan','Repair','Export','Deep')][string]$Mode='Menu')

$ErrorActionPreference = 'Stop'
$LFVersion = '1.2.0-preview'
$LFWindowsId = '55c92734-d682-4d71-983e-d6ec3f16059f'
$LFOfficeId = '0ff1ce15-a989-479d-af46-f275c6370663'
$LFBackups = Join-Path $env:ProgramData 'LicenseFix\Backups'
$LFReports = Join-Path $env:ProgramData 'LicenseFix\Reports'
$LFHosts = @('kms.digiboy.ir','kms.msguides.com','kms8.msguides.com','kms9.msguides.com')
$LFSuffixes = @('digiboy.ir','msguides.com','zpale.com','chinancce.com','03k.org','crsoo.com','loli.beer')
$LFLastScan = $null

function LF-Title([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 68) -ForegroundColor Cyan
    Write-Host (' LicenseFix ' + $LFVersion + ' | ' + $Text) -ForegroundColor Cyan
    Write-Host ('=' * 68) -ForegroundColor Cyan
}
function LF-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function LF-ReadValue([string]$Path,[string]$Name) {
    try { return (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $null }
}
function LF-KmsKind([string]$HostName) {
    $h = $HostName.Trim().Trim('"').ToLowerInvariant()
    if ($h -eq '' -or $h -eq '0.0.0.0') { return 'CLEARED' }
    if ($h -eq '10.0.0.10' -or $h -eq '127.0.0.2' -or $h -match '^(localhost|127\.|::1)') { return 'SUSPICIOUS' }
    if ($LFHosts -contains $h) { return 'SUSPICIOUS' }
    foreach ($suffix in $LFSuffixes) {
        if ($h -eq $suffix -or $h.EndsWith('.' + $suffix)) { return 'SUSPICIOUS' }
    }
    # Enterprise, Azure, and unknown hosts require review; NEVER auto-delete.
    return 'REVIEW'
}
function LF-AddIssue($Issues,[string]$Id,[string]$Scope,[string]$Level,
                     [string]$Reason,[string]$Evidence,[bool]$CanFix,
                     [string]$Path='', [string]$Name='',[string]$Expected='') {
    [void]$Issues.Add([pscustomobject]@{
        Id=$Id; Scope=$Scope; Level=$Level; Reason=$Reason; Evidence=$Evidence;
        CanFix=$CanFix; RegistryPath=$Path; ValueName=$Name; ExpectedValue=$Expected
    })
}
function LF-Scan {
    $issues = New-Object 'System.Collections.Generic.List[object]'
    $notes = New-Object 'System.Collections.Generic.List[string]'
    $domain = $true  # Fail closed if domain membership query fails.
    try { $domain = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain }
    catch { [void]$notes.Add('Could not query domain membership: all repairs disabled.') }
    $all = @()
    try {
        $all = @(Get-CimInstance SoftwareLicensingProduct -ErrorAction Stop | Where-Object {
            $_.PartialProductKey -and $_.ApplicationID -in @($LFWindowsId,$LFOfficeId)
        })
    } catch { [void]$notes.Add('Failed to read SPP license products; repairs disabled.') }
    $win = @($all | Where-Object ApplicationID -EQ $LFWindowsId)
    $office = @($all | Where-Object ApplicationID -EQ $LFOfficeId)
    $winLicensed = @($win | Where-Object LicenseStatus -EQ 1)
    $officeLicensed = @($office | Where-Object LicenseStatus -EQ 1)
    $office2010 = @()
    try { $office2010 = @(Get-CimInstance OfficeSoftwareProtectionProduct -ErrorAction Stop | Where-Object PartialProductKey) }
    catch {}
    $officeSeen = $office.Count + $office2010.Count
    $officeValid = ($officeSeen -eq 0 -or $officeLicensed.Count -gt 0 -or @($office2010 | Where-Object LicenseStatus -EQ 1).Count -gt 0)
    $kmsVolume = $false
    foreach ($p in @($all) + @($office2010)) {
        if ([string]$p.ProductKeyChannel -match 'KMSCLIENT|GVLK' -or [string]$p.Description -match 'VOLUME_KMSCLIENT') { $kmsVolume = $true }
    }
    $safe = (-not $domain -and $winLicensed.Count -gt 0 -and $officeValid -and -not $kmsVolume)
    if ($winLicensed.Count -eq 0) { LF-AddIssue $issues 'WIN-STATUS' 'Windows' 'REVIEW' 'No licensed Windows product was confirmed' 'Check Settings > Activation and slmgr /dlv' $false }
    if (-not $officeValid) { LF-AddIssue $issues 'OFF-STATUS' 'Office' 'REVIEW' 'Office product is present but not confirmed licensed' 'Verify through Office account and official activation' $false }
    if ($officeSeen -eq 0) { [void]$notes.Add('Office M365 vNext licensing may not be visible in SoftwareLicensingProduct.') }
    if ($domain) { [void]$notes.Add('Domain joined OR domain check failed: auto-repair disabled.') }
    if ($kmsVolume) { [void]$notes.Add('KMS/Volume product found: enterprise licensing may be legitimate; auto-repair disabled.') }

    foreach ($p in $all) {
        $hostName = [string]$p.KeyManagementServiceMachine
        if ([string]::IsNullOrWhiteSpace($hostName)) { continue }
        if ((LF-KmsKind $hostName) -eq 'CLEARED') { continue }
        $scope = if ($p.ApplicationID -eq $LFOfficeId) { 'Office' } else { 'Windows' }
        LF-AddIssue $issues 'WMI-KMS' $scope 'REVIEW' 'KMS machine present in WMI license record' ("$($p.Name): $hostName") $false
    }

    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform',
        'HKLM:\SOFTWARE\Microsoft\OfficeSoftwareProtectionPlatform',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\OfficeSoftwareProtectionPlatform',
        'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun'
    )
    $number = 0
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $keys = @($root)
        try { $keys += @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction SilentlyContinue | Select-Object -First 3000 | ForEach-Object PSPath) }
        catch { [void]$notes.Add("Cannot enumerate every subkey under $root") }
        foreach ($key in $keys) {
            $h = [string](LF-ReadValue $key 'KeyManagementServiceName')
            if ([string]::IsNullOrWhiteSpace($h)) { continue }
            $kind = LF-KmsKind $h
            if ($kind -eq 'CLEARED') { continue }
            $number++
            $scope = if ($key -match '0ff1ce15-' -or $root -match 'Office') { 'Office' } else { 'Shared' }
            LF-AddIssue $issues ("KMS-{0:d3}" -f $number) $scope $kind 'Stored KMS server configuration' ("$key -> $h") ($safe -and $kind -eq 'SUSPICIOUS') $key 'KeyManagementServiceName' $h
        }
    }
    $policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
    $noGen = LF-ReadValue $policy 'NoGenTicket'
    if ([string]$noGen -eq '1') {
        LF-AddIssue $issues 'POL-001' 'Shared' 'REVIEW' 'NoGenTicket=1 policy requires review' $policy $safe $policy 'NoGenTicket' '1'
    }

    $store = Join-Path $env:SystemRoot 'System32\spp\store\2.0'
    foreach ($name in @('data.dat','tokens.dat')) {
        $p = Join-Path $store $name
        if (Test-Path -LiteralPath $p) {
            $time = (Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue).LastWriteTime
            if ($time) { [void]$notes.Add("SPP $name last modified $time (informational only; never alter timestamps).") }
        }
    }
    foreach ($serviceName in @('KMSpico','KMService','AutoKMS','KMSAuto','vlmcsd')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) { LF-AddIssue $issues 'SERVICE' 'Shared' 'REVIEW' 'Check suspicious activation service' $service.Name $false }
    }
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            if ($task.TaskName -match 'AutoKMS|AutoPico|KMSAuto|KMSpico|Activation-Renewal') {
                LF-AddIssue $issues 'TASK' 'Shared' 'REVIEW' 'Review scheduled activation task' ("$($task.TaskPath)$($task.TaskName)") $false
            }
        }
    } catch {}
    return [pscustomobject]@{
        Version=$LFVersion; Timestamp=(Get-Date).ToString('o'); Computer=$env:COMPUTERNAME;
        WindowsLicensed=($winLicensed.Count -gt 0);
        WindowsChannel=$(if($winLicensed.Count){[string]$winLicensed[0].ProductKeyChannel}else{'Unknown'});
        OfficeDetected=$officeSeen; OfficeSafe=$officeValid; DomainJoinedOrUnknown=$domain;
        KmsVolume=$kmsVolume; RepairEligible=$safe;
        Issues=@($issues.ToArray()); Notes=@($notes.ToArray())
    }
}
function LF-Show($Scan) {
    LF-Title 'Windows / Office diagnostic'
    Write-Host "Computer: $($Scan.Computer); Windows Licensed: $($Scan.WindowsLicensed); Channel: $($Scan.WindowsChannel)"
    Write-Host "Office products in WMI: $($Scan.OfficeDetected); KMS Volume: $($Scan.KmsVolume)"
    Write-Host "Domain/unknown: $($Scan.DomainJoinedOrUnknown); Safe repair eligibility: $($Scan.RepairEligible)"
    foreach ($issue in $Scan.Issues) {
        $color=if($issue.CanFix){'Yellow'}else{'Gray'}
        Write-Host "[$($issue.Id)] $($issue.Scope) $($issue.Level): $($issue.Reason)" -ForegroundColor $color
        Write-Host "    $($issue.Evidence)"
        Write-Host "    Eligible for confirmed cleanup: $($issue.CanFix)"
    }
    if ($Scan.Issues.Count -eq 0) { Write-Host 'No findings in the implemented v1 checks.' -ForegroundColor Green }
    foreach ($note in $Scan.Notes) { Write-Host "[INFO] $note" -ForegroundColor Gray }
    Write-Host "TOTAL: $($Scan.Issues.Count) findings" -ForegroundColor Cyan
    Write-Warning 'A green scanner result is not proof of valid license ownership. Check purchase documentation.'
}
function LF-Export($Scan) {
    New-Item -Path $LFReports -ItemType Directory -Force | Out-Null
    $p = Join-Path $LFReports ('scan-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
    $Scan | ConvertTo-Json -Depth 7 | Out-File -LiteralPath $p -Encoding UTF8
    Write-Host "Saved report: $p"
}
function LF-NativePath([string]$Path) {
    if ($Path -match '^HKLM:\\') { return ($Path -replace '^HKLM:\\','HKLM\') }
    if ($Path -match '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\') {
        return ($Path -replace '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\','HKLM\')
    }
    if ($Path -match '^Registry::HKEY_LOCAL_MACHINE\\') {
        return ($Path -replace '^Registry::HKEY_LOCAL_MACHINE\\','HKLM\')
    }
    throw "Unsupported Registry path: $Path"
}
function LF-Repair($Scan) {
    LF-Title 'Backup and confirmed residual Registry cleanup'
    if (-not (LF-Admin)) { Write-Warning 'Open PowerShell as Administrator for repairs.'; return }
    if (-not $Scan.RepairEligible) { Write-Warning 'Safety lock: Windows/Office licensing or domain/KMS policy requires review. Nothing changed.'; return }
    $fixes = @($Scan.Issues | Where-Object { $_.CanFix -and $_.RegistryPath -and $_.ValueName })
    if ($fixes.Count -eq 0) { Write-Host 'No values eligible for automatic repair.'; return }
    foreach ($f in $fixes) { Write-Host ("PLAN {0}: {1} / {2} = {3}" -f $f.Id,$f.RegistryPath,$f.ValueName,$f.ExpectedValue) }
    Write-Warning 'Remove only values shown above. Never delete entire keys or SPP license store files.'
    if ((Read-Host 'Type SUA to BACKUP then remove ONLY the listed values') -cne 'SUA') {
        Write-Host 'Cancelled. No changes made.'; return
    }
    $backup = Join-Path $LFBackups (Get-Date -Format 'yyyyMMdd-HHmmss')
    New-Item -Path $backup -ItemType Directory -Force | Out-Null
    $fixes | ConvertTo-Json -Depth 5 | Out-File -LiteralPath (Join-Path $backup 'repair-plan.json') -Encoding UTF8
    $paths = @($fixes | Select-Object -ExpandProperty RegistryPath -Unique)
    $n = 0
    # Back up ALL affected Registry keys successfully before making any change.
    foreach ($path in $paths) {
        $native = LF-NativePath $path
        $regfile = Join-Path $backup ("registry-{0:d3}.reg" -f (++$n))
        & reg.exe export $native $regfile /y | Out-Null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $regfile)) {
            throw "BACKUP FAILED at $native. No Registry values were removed."
        }
    }
    Write-Host "Registry backups: $backup" -ForegroundColor Green
    foreach ($f in $fixes) {
        $current = LF-ReadValue $f.RegistryPath $f.ValueName
        if ([string]$current -cne [string]$f.ExpectedValue) {
            Write-Warning "Skipping $($f.Id): value changed after scan."; continue
        }
        try {
            Remove-ItemProperty -LiteralPath $f.RegistryPath -Name $f.ValueName -ErrorAction Stop
            Write-Host "Removed $($f.Id): $($f.ValueName)" -ForegroundColor Green
        } catch { Write-Warning "Could not remove $($f.Id): $($_.Exception.Message)" }
    }
    Write-Warning 'Do not blindly import backup .reg files; review present licensing state first.'
    LF-Show (LF-Scan)
}

# Preview: extended read-only evidence; exact diagnosis matters more than a fake green badge.
function LF-DeepScan {
    $result = LF-Scan
    $extra = New-Object 'System.Collections.Generic.List[object]'
    $incomplete = New-Object 'System.Collections.Generic.List[string]'
    $mk = {
        param([string]$group,[string]$detail)
        [void]$extra.Add([pscustomobject]@{ Group=$group; Status='REVIEW'; Evidence=$detail; CanFix=$false })
    }
    # A KMS listener alone is not proof of an unauthorized activation.
    try {
        if (Get-Command Get-NetTCPConnection -ErrorAction SilentlyContinue) {
            $listeners = @(Get-NetTCPConnection -LocalPort 1688 -State Listen -ErrorAction SilentlyContinue)
            foreach ($listener in $listeners) {
                & $mk '05' ("KMS port 1688 listening; PID=" + $listener.OwningProcess)
            }
        } else { [void]$incomplete.Add('05 - network cmdlet not available') }
    } catch { [void]$incomplete.Add('05 - port check failed') }

    foreach ($path in @((Join-Path $env:windir 'AutoKMS'),(Join-Path $env:windir 'AutoPico'),(Join-Path $env:ProgramData 'KMSpico'))) {
        if (Test-Path -LiteralPath $path) { & $mk '06' ("Possible activation tool artifact: " + $path) }
    }
    $binary = Join-Path $env:windir 'System32\sppsvc.exe'
    try {
        if (Test-Path -LiteralPath $binary) {
            $sig = Get-AuthenticodeSignature -LiteralPath $binary -ErrorAction Stop
            if ($sig.Status -ne 'Valid') { & $mk '07' ("sppsvc.exe signature=" + $sig.Status) }
        } else { & $mk '07' 'sppsvc.exe is missing' }
    } catch { [void]$incomplete.Add('07 - cannot verify Windows SPP signature') }

    # Read-only hosts inspection, no alteration of evidence or timestamps.
    $hostsFile = Join-Path $env:windir 'System32\drivers\etc\hosts'
    try {
        if (Test-Path -LiteralPath $hostsFile) {
            $number = 0
            foreach ($line in @(Get-Content -LiteralPath $hostsFile -ErrorAction Stop)) {
                $number++
                $activeLine = ($line -split '#',2)[0].Trim()
                if ($activeLine -match '(?i)(activation\.sls\.microsoft\.com|validation\.sls\.microsoft\.com|licensing\.mp\.microsoft\.com)') {
                    & $mk '14' ("Hosts line " + $number + ": " + $activeLine)
                }
            }
        }
    } catch { [void]$incomplete.Add('14 - cannot inspect hosts file') }

    # Office license DLLs in VFS: review signatures and source, do not auto-delete.
    $bases = @($env:ProgramFiles, [Environment]::GetFolderPath('ProgramFilesX86'))
    foreach ($base in $bases) {
        if (-not $base) { continue }
        foreach ($sub in @('Microsoft Office\root\vfs\System','Microsoft Office\root\vfs\SystemX86')) {
            $dir = Join-Path $base $sub
            if (-not (Test-Path -LiteralPath $dir)) { continue }
            try {
                foreach ($dll in @(Get-ChildItem -LiteralPath $dir -Filter 'sppc*.dll' -File -ErrorAction Stop)) {
                    $hash = (Get-FileHash -LiteralPath $dll.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
                    & $mk '16' ("Office licensing DLL needs provenance review: " + $dll.FullName + "; SHA256=" + $hash)
                }
            } catch { [void]$incomplete.Add('16 - VFS inspection incomplete') }
        }
    }
    return [pscustomobject]@{
        Scan=$result; ExtendedFindings=@($extra.ToArray()); Incomplete=@($incomplete.ToArray());
        Disclaimer='Preview only. 19 checks NOT implemented. Never fake green, change SPP timestamps or delete audit history.'
    }
}
function LF-DeepMode {
    do {
        LF-Title 'Sua loi chuyen sau - PREVIEW'
        Write-Host ' 1. Quet mo rong (chi doc)'
        Write-Host ' 2. Lap phuong an sua an toan (dry-run)'
        Write-Host ' 3. Sao luu + sua Registry da xac minh + quet lai'
        Write-Host ' 4. Xuat bao cao chuyen sau JSON'
        Write-Host ' 0. Quay lai'
        $action = Read-Host 'Chon'
        switch ($action) {
            '1' {
                $data=LF-DeepScan; LF-Show $data.Scan
                foreach ($finding in $data.ExtendedFindings) {
                    Write-Host ("[REVIEW #{0}] {1}" -f $finding.Group,$finding.Evidence) -ForegroundColor Yellow
                }
                foreach ($missing in $data.Incomplete) { Write-Warning ("Kiem tra chua day du: " + $missing) }
                Write-Warning 'Chua co day du 19 phep kiem tra. Khong duoc bao cao 19/19 xanh.'
            }
            '2' {
                $data=LF-DeepScan; LF-Show $data.Scan
                $fixes=@($data.Scan.Issues | Where-Object { $_.CanFix -and $_.RegistryPath -and $_.ValueName })
                foreach ($fix in $fixes) { Write-Host ("[DRY RUN] Xem xet xoa {0}: {1}" -f $fix.RegistryPath,$fix.ValueName) }
                if ($fixes.Count -eq 0) { Write-Host 'Khong co gia tri Registry nao duoc phep tu sua.' }
                Write-Warning 'Cac phat hien chuyen sau chi duoc bao cao; can xac minh truoc khi sua.'
            }
            '3' {
                $before=LF-DeepScan
                LF-Repair $before.Scan
                $after=LF-DeepScan
                LF-Show $after.Scan
                Write-Host ("Can xem xet them: " + $after.ExtendedFindings.Count)
            }
            '4' {
                $data=LF-DeepScan
                New-Item -Path $LFReports -ItemType Directory -Force | Out-Null
                $out=Join-Path $LFReports ('deep-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
                $data | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $out -Encoding UTF8
                Write-Host ("Bao cao: " + $out) -ForegroundColor Green
            }
            '0' { break }
            default { Write-Warning 'Lua chon khong hop le' }
        }
        if ($action -ne '0') { [void](Read-Host 'Nhan Enter de tiep tuc') }
    } while ($action -ne '0')
}

function LF-Menu {
    do {
        LF-Title 'Main menu'
        Write-Host ' 1. Diagnose (read-only)'
        Write-Host ' 2. Scan and show safe repair plan'
        Write-Host ' 3. Backup + confirm Registry cleanup + rescan'
        Write-Host ' 4. Export JSON diagnostics'
        Write-Host ' 5. Run sfc /verifyonly (read-only)'
        Write-Host ' 6. Sua loi chuyen sau - preview'
        Write-Host ' 0. Exit'
        $choice = Read-Host 'Choose'
        switch($choice) {
            '1' { $script:LFLastScan=LF-Scan; LF-Show $script:LFLastScan }
            '2' { $script:LFLastScan=LF-Scan; LF-Show $script:LFLastScan }
            '3' { $script:LFLastScan=LF-Scan; LF-Show $script:LFLastScan; LF-Repair $script:LFLastScan }
            '4' { if(-not $script:LFLastScan){$script:LFLastScan=LF-Scan}; LF-Export $script:LFLastScan }
            '5' { & sfc.exe /verifyonly }
            '6' { LF-DeepMode }
            '0' { break }
            default { Write-Warning 'Invalid option' }
        }
        if ($choice -ne '0') { [void](Read-Host 'Press Enter to continue') }
    } while ($choice -ne '0')
}
if (-not $env:SystemRoot) { throw 'Windows only.' }
switch ($Mode) {
    'Scan'   { LF-Show (LF-Scan) }
    'Plan'   { LF-Show (LF-Scan) }
    'Repair' { $scan=LF-Scan; LF-Show $scan; LF-Repair $scan }
    'Export' { $scan=LF-Scan; LF-Export $scan }
    'Deep'   { LF-DeepMode }
    default  { LF-Menu }
}
