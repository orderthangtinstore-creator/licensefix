#requires -Version 5.1
<#
LicenseFix v2.0.0-beta - Windows/Office license diagnostics and scoped remediation.
Preview build: test on a lab PC before performing repairs.
Independent project. Not affiliated with Microsoft or license.info.vn.
Repairs only specifically reviewed Registry values after successful backups.
Never edits SPP data.dat/tokens.dat, license keys, history, or timestamps.
#>
[CmdletBinding()]
param([ValidateSet('Menu','Scan','Plan','Repair','Export','Deep')][string]$Mode='Menu')

$ErrorActionPreference = 'Stop'
$LFVersion = '2.0.0-beta'
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

# LICENSEFIX DEEP REPAIR 2.0 - STAGED, EVIDENCE-BASED
function LF-DeepItem([int]$Id,[string]$Name,[string]$Status,[string]$Evidence,[string]$Action){
    [pscustomobject]@{Id=$Id;Name=$Name;Status=$Status;Evidence=$Evidence;Action=$Action}
}
function LF-DeepInspect {
    $base=LF-Scan
    $titles=@(
      'Thông tin Windows/OEM BIOS','Windows SPP/WMI','Office SPP/OSPP',
      'KMS Windows','Cổng 1688 / giả lập KMS','Dấu vết công cụ kích hoạt',
      'Chữ ký tệp SPP','TSforge/KMS38 Windows','HWID/GenuineTicket',
      'Windows rearm','Scheduled Tasks','Microsoft Defender',
      'Lịch sử lệnh PowerShell','Tệp hosts','Thời gian kho SPP',
      'Office Ohook','KMS Office','Office Retail/Volume','TSforge Office'
    )
    $items=New-Object 'System.Collections.Generic.List[object]'
    for($i=1;$i -le 19;$i++){
      [void]$items.Add((LF-DeepItem $i $titles[$i-1] 'NOT_CHECKED' 'Chưa có bằng chứng đầy đủ.' 'Cần kiểm tra theo nguồn chính thức.'))
    }
    $rows=$items.ToArray()
    try {
      $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
      $rows[0].Status='PASS';$rows[0].Evidence=[string]$os.Caption
      $rows[0].Action='Không hiển thị product key.'
    }catch{}
    $rows[1].Status=if($base.WindowsLicensed){'PASS'}else{'WARN'}
    $rows[1].Evidence="Licensed=$($base.WindowsLicensed); Channel=$($base.WindowsChannel)"
    $rows[1].Action='Đối chiếu slmgr /dlv với quyền sử dụng.'
    if($base.OfficeDetected -gt 0){
      $rows[2].Status=if($base.OfficeSafe){'PASS'}else{'WARN'}
      $rows[2].Evidence="Office WMI: $($base.OfficeDetected); Valid=$($base.OfficeSafe)"
      $rows[2].Action='Kiểm tra Office Account và giấy phép cho từng SKU.'
    }
    $kmsWin=@($base.Issues|Where-Object {$_.Id -like 'KMS-*' -and $_.Scope -ne 'Office'})
    $rows[3].Status=if($kmsWin.Count){'WARN'}elseif($base.KmsVolume){'REVIEW'}else{'PASS'}
    $rows[3].Evidence=if($kmsWin.Count){($kmsWin.Evidence -join '; ')}else{'Không thấy cấu hình KMS bất thường trong phạm vi v1.'}
    $rows[3].Action='Không xóa KMS doanh nghiệp; chỉ dọn cấu hình tồn dư sau khi sao lưu.'
    try{
      $listen=@(Get-NetTCPConnection -LocalPort 1688 -State Listen -ErrorAction Stop)
      $rows[4].Status=if($listen.Count){'REVIEW'}else{'PASS'}
      $rows[4].Evidence="TCP 1688 listeners: $($listen.Count)"
      $rows[4].Action='Xác minh PID và chữ ký service; không tự dừng tiến trình.'
    }catch{}
    $pathHits=@()
    foreach($path in @("$env:windir\AutoKMS","$env:windir\AutoPico","$env:ProgramData\KMSpico","$env:windir\System32\SppExtComObjHook.dll")){
      if(Test-Path -LiteralPath $path){$pathHits+= $path}
    }
    $rows[5].Status='REVIEW'
    $rows[5].Evidence=if($pathHits.Count){$pathHits -join '; '}else{'Không thấy 4 vị trí phổ biến; chưa quét tất cả đường dẫn.'}
    $rows[5].Action='Đối chiếu hash, publisher và phần mềm cài đặt trước khi gỡ.'
    try{
      $sp=Join-Path $env:windir 'System32\sppsvc.exe'
      $s=Get-AuthenticodeSignature -LiteralPath $sp -ErrorAction Stop
      $rows[6].Status=if($s.Status -eq 'Valid'){'REVIEW'}else{'WARN'}
      $rows[6].Evidence="sppsvc.exe signature=$($s.Status); chỉ kiểm tra tệp đại diện."
      $rows[6].Action='SFC/DISM để kiểm tra tệp hệ thống; không thay DLL thủ công.'
    }catch{}
    $rows[7].Action='Đối chiếu bằng chứng SPP/WMI; không xóa kho SPP do nghi vấn đơn lẻ.'
    $rows[8].Action='Kiểm tra giấy phép số bằng cơ chế Microsoft; không tạo GenuineTicket giả.'
    try{
      $wmi=Get-CimInstance SoftwareLicensingService -ErrorAction Stop
      $rows[9].Status='REVIEW'
      $rows[9].Evidence="Rearm Windows=$($wmi.RemainingWindowsReArmCount); SKU=$($wmi.RemainingSkuReArmCount)"
      $rows[9].Action='Đây là số liệu tham khảo, không reset.'
    }catch{}
    $taskHits=@($base.Issues|Where-Object {$_.Id -eq 'TASK'})
    $rows[10].Status='REVIEW'
    $rows[10].Evidence=if($taskHits.Count){$taskHits.Evidence -join '; '}else{'Không thấy task trùng mẫu phổ biến; actions chưa kiểm tra đủ.'}
    $rows[10].Action='Xem nội dung task và chữ ký phần mềm trước khi sửa.'
    try{
      $mp=Get-MpPreference -ErrorAction Stop
      $ex=@($mp.ExclusionPath|Where-Object {$_ -match '(?i)(KMS|AutoPico|Activation-Renewal)'})
      $rows[11].Status='REVIEW'
      $rows[11].Evidence=if($ex.Count){$ex -join '; '}else{'Không thấy ngoại lệ khớp tên phổ biến; chưa xét Defender history.'}
      $rows[11].Action='Tham khảo chính sách IT trước khi xóa ngoại lệ.'
    }catch{}
    $rows[12].Evidence='Không thu thập lịch sử riêng tư hay xóa dòng lệnh để né kiểm toán.'
    try{
      $hosts=Join-Path $env:windir 'System32\drivers\etc\hosts'
      $hits=@(Get-Content -LiteralPath $hosts -ErrorAction Stop|Where-Object {$_ -notmatch '^\s*#' -and $_ -match '(?i)(activation-v2\.sls\.microsoft\.com|validation-v2\.sls\.microsoft\.com)'})
      $rows[13].Status=if($hits.Count){'REVIEW'}else{'PASS'}
      $rows[13].Evidence=if($hits.Count){$hits -join '; '}else{'Không thấy chuyển hướng máy chủ Microsoft thuộc mẫu đang xét.'}
      $rows[13].Action='Sao lưu rồi mới xem xét chỉnh dòng hosts.'
    }catch{}
    $timestamps=@()
    foreach($fn in @('data.dat','tokens.dat')){
      $p=Join-Path $env:windir ("System32\spp\store\2.0\"+$fn)
      if(Test-Path -LiteralPath $p){
        $a=Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        if($a){$timestamps+= "$fn=$($a.LastWriteTime)"}
      }
    }
    $rows[14].Status='REVIEW'
    $rows[14].Evidence=$timestamps -join '; '
    $rows[14].Action='LastWriteTime không chứng minh crack; tuyệt đối không chỉnh thời gian để né scanner.'
    $dlls=@()
    foreach($p in @("$env:ProgramFiles\Microsoft Office\root\vfs\System","$env:ProgramFiles\Microsoft Office\root\vfs\SystemX86")){
      if(Test-Path -LiteralPath $p){$dlls+=@(Get-ChildItem -LiteralPath $p -Filter 'sppc*.dll' -ErrorAction SilentlyContinue|Select-Object -ExpandProperty FullName)}
    }
    $rows[15].Status='REVIEW'
    $rows[15].Evidence=if($dlls.Count){$dlls -join '; '}else{'Không tìm thấy DLL tại 2 thư mục VFS; chưa thẩm định Office toàn diện.'}
    $rows[15].Action='Xác minh chữ ký và dùng Microsoft Office Online Repair khi cần.'
    $offHits=@($base.Issues|Where-Object {$_.Scope -eq 'Office' -and ($_.Id -like 'KMS-*' -or $_.Id -eq 'WMI-KMS')})
    $rows[16].Status=if($offHits.Count){'WARN'}else{'REVIEW'}
    $rows[16].Evidence=if($offHits.Count){$offHits.Evidence -join '; '}else{'Không thấy máy chủ KMS Office ở bộ quét v1; chưa đủ phạm vi Office.'}
    $rows[16].Action='Xác minh Office OSPP/ClickToRun và giấy phép Volume hợp pháp.'
    $rows[17].Action='Đối chiếu ClickToRun ProductReleaseIds, SKU và chứng từ.'
    $rows[18].Action='Dùng kiểm tra cấp phép Office, không tự đặt lại kho SPP.'
    [pscustomobject]@{Version=$LFVersion;At=(Get-Date).ToString('o');Device=$env:COMPUTERNAME;Base=$base;Items=@($rows)}
}
function LF-DeepDisplay($Scan){
    LF-Title 'CHẨN ĐOÁN CHUYÊN SÂU - 19 NHÓM'
    foreach($item in $Scan.Items){
       $color=switch($item.Status){'PASS'{'Green'}'WARN'{'Red'}'REVIEW'{'Yellow'}default{'DarkGray'}}
       Write-Host ("[{0:d2}] {1} | {2}" -f $item.Id,$item.Status,$item.Name) -ForegroundColor $color
       Write-Host ("  {0}" -f $item.Evidence) -ForegroundColor Gray
       if($item.Status -ne 'PASS'){Write-Host ("  Gợi ý: {0}" -f $item.Action) -ForegroundColor DarkGray}
    }
    $p=@($Scan.Items|Where-Object Status -EQ 'PASS').Count
    $w=@($Scan.Items|Where-Object Status -EQ 'WARN').Count
    $r=@($Scan.Items|Where-Object Status -EQ 'REVIEW').Count
    $n=@($Scan.Items|Where-Object Status -EQ 'NOT_CHECKED').Count
    Write-Host ("Tổng: {0} đạt | {1} cảnh báo | {2} cần xác minh | {3} chưa kiểm tra" -f $p,$w,$r,$n) -ForegroundColor Cyan
    if($r -gt 0 -or $n -gt 0){Write-Warning 'Không thể kết luận 19/19 xanh khi có mục chưa xác minh hoặc chưa kiểm tra.'}
}
function LF-DeepReport($Scan,[string]$Stage='scan'){
    New-Item -ItemType Directory -Force -Path $LFReports | Out-Null
    $path=Join-Path $LFReports ('deep-{0}-{1}-{2}.json' -f $Stage,(Get-Date -Format 'yyyyMMdd-HHmmss'),([guid]::NewGuid().ToString('N').Substring(0,6)))
    [pscustomobject]@{Version=$Scan.Version;At=$Scan.At;Device=$Scan.Device;Stage=$Stage;Checks=$Scan.Items;Findings=$Scan.Base.Issues;WindowsLicensed=$Scan.Base.WindowsLicensed;Channel=$Scan.Base.WindowsChannel} | ConvertTo-Json -Depth 9 | Out-File -LiteralPath $path -Encoding UTF8
    Write-Host ('Đã ghi báo cáo: '+$path) -ForegroundColor Green
}
function LF-DeepSystem([string]$Tool){
    if(-not (LF-Admin)){Write-Warning 'Cần chạy PowerShell với quyền Administrator.';return}
    if($Tool -eq 'SFC'){
      if((Read-Host 'Gõ SFC để xác nhận sfc /scannow (có thể sửa file hệ thống)') -cne 'SFC'){return}
      & sfc.exe /scannow
    }else{
      if((Read-Host 'Gõ DISM để xác nhận DISM /RestoreHealth (có thể sửa component store)') -cne 'DISM'){return}
      & dism.exe /Online /Cleanup-Image /RestoreHealth
    }
    Write-Host ('Exit code: '+$LASTEXITCODE)
    Write-Warning 'Sau sửa, phải kiểm tra lại trạng thái bản quyền và khởi động lại nếu hệ thống yêu cầu.'
}
function LF-DeepMenu {
  $scan=$null
  do {
    LF-Title 'DEEP REPAIR 2.0 BETA'
    Write-Host ' 1. Quét 19 nhóm và hiển thị bằng chứng'
    Write-Host ' 2. Xem phương án sửa có chọn lọc (Dry-run)'
    Write-Host ' 3. Sao lưu + sửa Registry đủ điều kiện + quét lại'
    Write-Host ' 4. SFC /scannow (xác nhận riêng)'
    Write-Host ' 5. DISM /RestoreHealth (xác nhận riêng)'
    Write-Host ' 6. Xuất báo cáo JSON'
    Write-Host ' 0. Trở về'
    $choice=Read-Host 'Chọn'
    switch($choice){
      '1' { $scan=LF-DeepInspect; LF-DeepDisplay $scan }
      '2' {
        $scan=LF-DeepInspect; LF-DeepDisplay $scan
        $fix=@($scan.Base.Issues|Where-Object CanFix)
        if($fix.Count){$fix|Select-Object Id,Scope,Evidence|Format-Table -AutoSize|Out-Host}
        else{Write-Host 'Không có mục Registry đủ điều kiện sửa an toàn.'}
      }
      '3' {
        $scan=LF-DeepInspect; LF-DeepReport $scan 'before'
        LF-Repair $scan.Base
        $scan=LF-DeepInspect; LF-DeepReport $scan 'after'; LF-DeepDisplay $scan
      }
      '4' {LF-DeepSystem 'SFC'}
      '5' {LF-DeepSystem 'DISM'}
      '6' {if(-not $scan){$scan=LF-DeepInspect};LF-DeepReport $scan 'manual'}
      '0' {}
      default {Write-Warning 'Lựa chọn không hợp lệ.'}
    }
    if($choice -ne '0'){[void](Read-Host 'Enter để tiếp tục')}
  }while($choice -ne '0')
}

function LF-Menu {
    do {
        LF-Title 'Main menu'
        Write-Host ' 1. Diagnose (read-only)'
        Write-Host ' 2. Scan and show safe repair plan'
        Write-Host ' 3. Backup + confirm Registry cleanup + rescan'
        Write-Host ' 4. Export JSON diagnostics'
        Write-Host ' 5. Run sfc /verifyonly (read-only)'
        Write-Host ' 6. Deep Repair: 19 nhóm, sao lưu và sửa có kiểm soát'
        Write-Host ' 0. Exit'
        $choice = Read-Host 'Choose'
        switch($choice) {
            '1' { $script:LFLastScan=LF-Scan; LF-Show $script:LFLastScan }
            '2' { $script:LFLastScan=LF-Scan; LF-Show $script:LFLastScan }
            '3' { $script:LFLastScan=LF-Scan; LF-Show $script:LFLastScan; LF-Repair $script:LFLastScan }
            '4' { if(-not $script:LFLastScan){$script:LFLastScan=LF-Scan}; LF-Export $script:LFLastScan }
            '5' { & sfc.exe /verifyonly }
            '6' { LF-DeepMenu }
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
    'Deep' { LF-DeepMenu }
    default  { LF-Menu }
}
