#requires -Version 5.1
<#
LicenseFix v2.0.1-beta - Windows/Office license diagnostics and scoped remediation.
Preview build: test on a lab PC before performing repairs.
Independent project. Not affiliated with Microsoft or license.info.vn.
Repairs only specifically reviewed Registry values after successful backups.
Never edits SPP data.dat/tokens.dat, license keys, history, or timestamps.
#>
[CmdletBinding()]
param([ValidateSet('Menu','Scan','Plan','Repair','Export','Deep')][string]$Mode='Menu')

$ErrorActionPreference = 'Stop'
$LFVersion = '2.0.1-beta'
$LFWindowsId = '55c92734-d682-4d71-983e-d6ec3f16059f'
$LFOfficeId = '0ff1ce15-a989-479d-af46-f275c6370663'
$LFBackups = Join-Path $env:ProgramData 'LicenseFix\Backups'
$LFReports = Join-Path $env:ProgramData 'LicenseFix\Reports'
$LFHosts = @('kms.digiboy.ir','kms.msguides.com','kms8.msguides.com','kms9.msguides.com')
$LFSuffixes = @('digiboy.ir','msguides.com','zpale.com','chinancce.com','03k.org','crsoo.com','loli.beer')
$LFLastScan = $null

function LF-Title([string]$Text) {
    Write-Host ''
    Write-Host ('=' * 56) -ForegroundColor Cyan
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
    $watch=[Diagnostics.Stopwatch]::StartNew()
    Write-Host ' [1/3] Đang xác minh giấy phép...' -ForegroundColor DarkCyan
    $issues = New-Object 'System.Collections.Generic.List[object]'
    $notes = New-Object 'System.Collections.Generic.List[string]'
    $domain = $true  # Fail closed if domain membership query fails.
    try { $domain = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain }
    catch { [void]$notes.Add('Không đọc được trạng thái domain; đã khóa chức năng sửa.') }
    $all = @()
    try {
        $filter = "ApplicationID='$LFWindowsId' OR ApplicationID='$LFOfficeId'"
        try {
            $all = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter $filter -ErrorAction Stop |
              Where-Object { $_.PartialProductKey -and $_.ApplicationID -in @($LFWindowsId,$LFOfficeId) })
            if($all.Count -eq 0) {
                $all = @(Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction Stop |
                  Where-Object { $_.PartialProductKey -and $_.ApplicationID -in @($LFWindowsId,$LFOfficeId) })
            }
        } catch {
            [void]$notes.Add('WMI không hỗ trợ bộ lọc; dùng truy vấn đầy đủ.')
            $all = @(Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction Stop |
              Where-Object { $_.PartialProductKey -and $_.ApplicationID -in @($LFWindowsId,$LFOfficeId) })
        }
    } catch { [void]$notes.Add('Không đọc được dữ liệu cấp phép SPP; đã khóa chức năng sửa.') }
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
    if ($winLicensed.Count -eq 0) { LF-AddIssue $issues 'WIN-STATUS' 'Windows' 'REVIEW' 'Chưa xác minh được Windows đã kích hoạt' 'Kiểm tra Cài đặt > Kích hoạt và slmgr /dlv' $false }
    if (-not $officeValid) { LF-AddIssue $issues 'OFF-STATUS' 'Office' 'REVIEW' 'Office hiện diện nhưng chưa xác minh được giấy phép' 'Kiểm tra tài khoản Office và cơ chế kích hoạt chính thức' $false }
    if ($officeSeen -eq 0) { [void]$notes.Add('Microsoft 365 vNext có thể không xuất hiện trong SoftwareLicensingProduct.') }
    if ($domain) { [void]$notes.Add('Máy thuộc domain hoặc chưa xác minh được domain: không tự sửa.') }
    if ($kmsVolume) { [void]$notes.Add('Có giấy phép KMS/Volume có thể hợp lệ của tổ chức: không tự sửa.') }

    Write-Host ' [2/3] Đang kiểm tra KMS/Registry...' -ForegroundColor DarkCyan
    foreach ($p in $all) {
        $hostName = [string]$p.KeyManagementServiceMachine
        if ([string]::IsNullOrWhiteSpace($hostName)) { continue }
        if ((LF-KmsKind $hostName) -eq 'CLEARED') { continue }
        $scope = if ($p.ApplicationID -eq $LFOfficeId) { 'Office' } else { 'Windows' }
        LF-AddIssue $issues 'WMI-KMS' $scope 'REVIEW' 'Có máy chủ KMS trong dữ liệu WMI' ("$($p.Name): $hostName") $false
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
        try {
            if ($root -match 'Office\\ClickToRun$') {
                $keys += @(Get-ChildItem -LiteralPath $root -ErrorAction Stop | ForEach-Object PSPath)
                [void]$notes.Add('ClickToRun: chỉ quét gốc và nhánh trực tiếp; chưa quét mọi cấu hình.')
            } else {
                $children = @(Get-ChildItem -LiteralPath $root -Recurse -ErrorAction Stop | Select-Object -First 3001)
                if($children.Count -gt 3000){[void]$notes.Add("Chưa quét hết Registry: $root")}
                $keys += @($children | Select-Object -First 3000 | ForEach-Object PSPath)
            }
        } catch { [void]$notes.Add("Không thể quét hết Registry: $root") }
        foreach ($key in $keys) {
            $h = [string](LF-ReadValue $key 'KeyManagementServiceName')
            if ([string]::IsNullOrWhiteSpace($h)) { continue }
            $kind = LF-KmsKind $h
            if ($kind -eq 'CLEARED') { continue }
            $number++
            $scope = if ($key -match '0ff1ce15-' -or $root -match 'Office') { 'Office' } else { 'Shared' }
            LF-AddIssue $issues ("KMS-{0:d3}" -f $number) $scope $kind 'Còn cấu hình máy chủ KMS' ("$key -> $h") ($safe -and $kind -eq 'SUSPICIOUS') $key 'KeyManagementServiceName' $h
        }
    }
    $policy = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform'
    $noGen = LF-ReadValue $policy 'NoGenTicket'
    if ([string]$noGen -eq '1') {
        LF-AddIssue $issues 'POL-001' 'Shared' 'REVIEW' 'Chính sách NoGenTicket=1 cần xác minh' $policy $safe $policy 'NoGenTicket' '1'
    }

    $store = Join-Path $env:SystemRoot 'System32\spp\store\2.0'
    foreach ($name in @('data.dat','tokens.dat')) {
        $p = Join-Path $store $name
        if (Test-Path -LiteralPath $p) {
            $time = (Get-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue).LastWriteTime
            if ($time) { [void]$notes.Add("Thời gian sửa đổi SPP ${name}: $time (chỉ tham khảo, không chỉnh thời gian).") }
        }
    }
    Write-Host ' [3/3] Đang kiểm tra tác vụ và dịch vụ...' -ForegroundColor DarkCyan
    foreach ($serviceName in @('KMSpico','KMService','AutoKMS','KMSAuto','vlmcsd')) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service) { LF-AddIssue $issues 'SERVICE' 'Shared' 'REVIEW' 'Cần xác minh dịch vụ kích hoạt khả nghi' $service.Name $false }
    }
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            if ($task.TaskName -match 'AutoKMS|AutoPico|KMSAuto|KMSpico|Activation-Renewal') {
                LF-AddIssue $issues 'TASK' 'Shared' 'REVIEW' 'Cần xác minh tác vụ kích hoạt' ("$($task.TaskPath)$($task.TaskName)") $false
            }
        }
    } catch {}
    $watch.Stop()
    Write-Host (" Hoàn tất sau {0:n1} giây" -f $watch.Elapsed.TotalSeconds) -ForegroundColor DarkGreen
    return [pscustomobject]@{
        DurationMs=[math]::Round($watch.Elapsed.TotalMilliseconds,0);
        Version=$LFVersion; Timestamp=(Get-Date).ToString('o'); Computer=$env:COMPUTERNAME;
        WindowsLicensed=($winLicensed.Count -gt 0);
        WindowsChannel=$(if($winLicensed.Count){[string]$winLicensed[0].ProductKeyChannel}else{'Unknown'});
        OfficeDetected=$officeSeen; OfficeSafe=$officeValid; DomainJoinedOrUnknown=$domain;
        KmsVolume=$kmsVolume; RepairEligible=$safe;
        Issues=@($issues.ToArray()); Notes=@($notes.ToArray())
    }
}
function LF-Show($Scan) {
    LF-Title 'TỔNG QUAN WINDOWS / OFFICE'
    Write-Host (" Máy: {0}  |  Quét: {1:n1}s" -f $Scan.Computer,($Scan.DurationMs/1000))
    Write-Host (" Windows: {0}  |  Kênh: {1}" -f $(if($Scan.WindowsLicensed){'Đã kích hoạt'}else{'Chưa xác minh'}),$Scan.WindowsChannel)
    Write-Host (" Office: {0} sản phẩm WMI  |  KMS/Volume: {1}" -f $Scan.OfficeDetected,$Scan.KmsVolume)
    if(@($Scan.Issues).Count) {
        Write-Host (" {0} cảnh báo cần kiểm tra:" -f @($Scan.Issues).Count) -ForegroundColor Yellow
        foreach($it in $Scan.Issues){Write-Host ("  [{0}] {1}" -f $it.Id,$it.Reason) -ForegroundColor Yellow}
    } else {
        Write-Host ' Chưa phát hiện cảnh báo trong các phép kiểm đã hỗ trợ.' -ForegroundColor Green
    }
    if(@($Scan.Notes).Count) {Write-Host (" {0} ghi chú khác; xuất JSON để xem đủ." -f @($Scan.Notes).Count) -ForegroundColor DarkGray}
    Write-Host ' Kết quả không chứng minh quyền sở hữu bản quyền.' -ForegroundColor DarkGray
}
function LF-Export($Scan) {
    New-Item -Path $LFReports -ItemType Directory -Force | Out-Null
    $p = Join-Path $LFReports ('scan-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
    $Scan | ConvertTo-Json -Depth 7 | Out-File -LiteralPath $p -Encoding UTF8
    Write-Host "Đã lưu báo cáo: $p"
}
function LF-NativePath([string]$Path) {
    if ($Path -match '^HKLM:\\') { return ($Path -replace '^HKLM:\\','HKLM\') }
    if ($Path -match '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\') {
        return ($Path -replace '^Microsoft\.PowerShell\.Core\\Registry::HKEY_LOCAL_MACHINE\\','HKLM\')
    }
    if ($Path -match '^Registry::HKEY_LOCAL_MACHINE\\') {
        return ($Path -replace '^Registry::HKEY_LOCAL_MACHINE\\','HKLM\')
    }
    throw "Đường dẫn Registry không được hỗ trợ: $Path"
}
function LF-Repair($Scan,[switch]$SkipRescan) {
    $script:LFRepairChanged=$false
    LF-Title 'SAO LƯU VÀ SỬA REGISTRY'
    if (-not (LF-Admin)) { Write-Warning 'Hãy mở PowerShell với quyền Administrator để sửa lỗi.'; return }
    if (-not $Scan.RepairEligible) { Write-Warning 'Đã khóa sửa: cần đối chiếu giấy phép hoặc chính sách domain/KMS. Chưa thay đổi dữ liệu.'; return }
    $fixes = @($Scan.Issues | Where-Object { $_.CanFix -and $_.RegistryPath -and $_.ValueName })
    if ($fixes.Count -eq 0) { Write-Host 'Không có giá trị Registry đủ điều kiện xử lý.'; return }
    foreach ($f in $fixes) { Write-Host ("PLAN {0}: {1} / {2} = {3}" -f $f.Id,$f.RegistryPath,$f.ValueName,$f.ExpectedValue) }
    Write-Warning 'Chỉ xóa giá trị đã liệt kê. Không xóa cả khóa Registry hoặc kho SPP.'
    if ((Read-Host 'Gõ SUA để sao lưu và chỉ xóa các giá trị đã xác minh') -cne 'SUA') {
        Write-Host 'Đã hủy, không thay đổi dữ liệu.'; return
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
            throw "Sao lưu thất bại tại $native. Chưa xóa dữ liệu Registry."
        }
    }
    Write-Host "Bản sao Registry: $backup" -ForegroundColor Green
    foreach ($f in $fixes) {
        $current = LF-ReadValue $f.RegistryPath $f.ValueName
        if ([string]$current -cne [string]$f.ExpectedValue) {
            Write-Warning "Bỏ qua $($f.Id): giá trị đã thay đổi sau khi quét."; continue
        }
        try {
            Remove-ItemProperty -LiteralPath $f.RegistryPath -Name $f.ValueName -ErrorAction Stop
            $script:LFRepairChanged=$true
            Write-Host ("Đã xử lý: {0}" -f $f.Id) -ForegroundColor Green
        } catch { Write-Warning "Không thể xử lý $($f.Id): $($_.Exception.Message)" }
    }
    Write-Warning 'Không tự nhập lại bản sao .reg trước khi xác minh bản quyền.'
    if (-not $SkipRescan){LF-Show (LF-Scan)}
}

# LICENSEFIX DEEP REPAIR 2.0 - STAGED, EVIDENCE-BASED
function LF-DeepItem([int]$Id,[string]$Name,[string]$Status,[string]$Evidence,[string]$Action){
    [pscustomobject]@{Id=$Id;Name=$Name;Status=$Status;Evidence=$Evidence;Action=$Action}
}
function LF-DeepInspect {
    $deepWatch=[Diagnostics.Stopwatch]::StartNew()
    $base=LF-Scan
    Write-Host ' Đang hoàn thiện 19 nhóm kiểm tra...' -ForegroundColor DarkCyan
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
    $kmsIncomplete=@($base.Notes | Where-Object {$_ -match 'Registry'})
    $rows[3].Status=if($kmsWin.Count){'WARN'}elseif($base.KmsVolume -or $kmsIncomplete.Count){'REVIEW'}else{'PASS'}
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
    $deepWatch.Stop()
    [pscustomobject]@{Version=$LFVersion;At=(Get-Date).ToString('o');Device=$env:COMPUTERNAME;Base=$base;Items=@($rows);DurationMs=[math]::Round($deepWatch.Elapsed.TotalMilliseconds,0)}
}
function LF-DeepDisplay($Scan){
    LF-Title 'TỔNG QUAN QUÉT CHUYÊN SÂU'
    $p=@($Scan.Items|Where-Object Status -EQ 'PASS').Count
    $w=@($Scan.Items|Where-Object Status -EQ 'WARN').Count
    $r=@($Scan.Items|Where-Object Status -EQ 'REVIEW').Count
    $n=@($Scan.Items|Where-Object Status -EQ 'NOT_CHECKED').Count
    Write-Host (" Thiết bị: {0}  |  Quét nền: {1:n1}s" -f $Scan.Device,($Scan.DurationMs/1000))
    Write-Host (" {0} đạt  |  {1} cảnh báo  |  {2} cần xem  |  {3} chưa quét" -f $p,$w,$r,$n) -ForegroundColor Cyan
    Write-Host ('-'*56) -ForegroundColor DarkGray
    foreach($it in $Scan.Items) {
      $status=switch($it.Status){'PASS'{'ĐẠT'}'WARN'{'CẢNH BÁO'}'REVIEW'{'CẦN XEM'}default{'CHƯA QUÉT'}}
      $color=switch($it.Status){'PASS'{'Green'}'WARN'{'Red'}'REVIEW'{'Yellow'}default{'DarkGray'}}
      Write-Host (" {0,2}. {1,-10} {2}" -f $it.Id,$status,$it.Name) -ForegroundColor $color
    }
    Write-Host ('-'*56) -ForegroundColor DarkGray
    Write-Host ' Chọn mục 2 để xem bằng chứng của từng hạng mục.' -ForegroundColor Cyan
    if($n -or $r){Write-Host ' Chưa thể kết luận đạt đầy đủ 19 nhóm.' -ForegroundColor Yellow}
}
function LF-DeepDetail($Scan,[int]$Id) {
    if($Id -lt 1 -or $Id -gt 19){Write-Warning 'Nhập số từ 1 đến 19.';return}
    $it=$Scan.Items[$Id-1]
    LF-Title ("CHI TIẾT #{0:d2}" -f $Id)
    $label=switch($it.Status){'PASS'{'Đạt'}'WARN'{'Cảnh báo'}'REVIEW'{'Cần xem'}default{'Chưa quét'}}
    Write-Host (" {0}  |  {1}" -f $it.Name,$label) -ForegroundColor Cyan
    Write-Host ' Bằng chứng:' -ForegroundColor Gray
    Write-Host ("  {0}" -f $it.Evidence)
    Write-Host ' Đề xuất:' -ForegroundColor Gray
    Write-Host ("  {0}" -f $it.Action)
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
    LF-Title 'SỬA LỖI CHUYÊN SÂU'
    Write-Host ' 1. Quét và xem tổng quan'
    Write-Host ' 2. Xem chi tiết theo số mục'
    Write-Host ' 3. Xem trước kế hoạch sửa'
    Write-Host ' 4. Sao lưu và sửa Registry có xác nhận'
    Write-Host ' 5. Công cụ SFC / DISM'
    Write-Host ' 6. Xuất báo cáo JSON'
    Write-Host ' 0. Quay về'
    $choice=Read-Host 'Chọn'
    switch($choice) {
      '1' {$scan=LF-DeepInspect;LF-DeepDisplay $scan}
      '2' {
        if(-not $scan){Write-Host 'Chưa quét. Hãy chọn 1 trước.' -ForegroundColor Yellow}
        else {
          $id=0
          $inputId=Read-Host 'Nhập số hạng mục (1-19)'
          if([int]::TryParse($inputId,[ref]$id)){LF-DeepDetail $scan $id}
          else{Write-Warning 'Mã không hợp lệ.'}
        }
      }
      '3' {
        if(-not $scan){$scan=LF-DeepInspect}
        $fix=@($scan.Base.Issues|Where-Object CanFix)
        if($fix.Count){$fix|Select-Object Id,Scope,Reason|Format-Table -AutoSize|Out-Host}
        else{Write-Host 'Không có mục Registry đủ điều kiện sửa.' -ForegroundColor Yellow}
      }
      '4' {
        if(-not $scan){$scan=LF-DeepInspect}
        LF-DeepReport $scan 'before'
        LF-Repair $scan.Base -SkipRescan
        if($script:LFRepairChanged){
          $scan=LF-DeepInspect
          LF-DeepReport $scan 'after'
          LF-DeepDisplay $scan
        } else {Write-Host 'Không có thay đổi; bỏ qua quét lại.' -ForegroundColor Gray}
      }
      '5' {
        Write-Host ' 1. SFC /scannow   2. DISM /RestoreHealth   0. Hủy'
        $opt=Read-Host 'Chọn'
        if($opt -eq '1'){LF-DeepSystem 'SFC'}elseif($opt -eq '2'){LF-DeepSystem 'DISM'}
      }
      '6' {if(-not $scan){$scan=LF-DeepInspect};LF-DeepReport $scan 'manual'}
      '0' {}
      default {Write-Warning 'Lựa chọn không hợp lệ.'}
    }
    if($choice -ne '0'){[void](Read-Host 'Nhấn Enter để tiếp tục')}
  }while($choice -ne '0')
}
function LF-Menu {
  do {
    LF-Title 'MENU CHÍNH'
    Write-Host ' 1. Kiểm tra bản quyền Windows / Office'
    Write-Host ' 2. Xem đề xuất sửa lỗi'
    Write-Host ' 3. Sao lưu và sửa nhanh Registry'
    Write-Host ' 4. Xuất báo cáo JSON'
    Write-Host ' 5. Kiểm tra SFC (chỉ đọc)'
    Write-Host ' 6. Sửa lỗi chuyên sâu'
    Write-Host ' 0. Thoát'
    $choice=Read-Host 'Chọn'
    switch($choice) {
      '1' {$script:LFLastScan=LF-Scan;LF-Show $script:LFLastScan}
      '2' {if(-not $script:LFLastScan){$script:LFLastScan=LF-Scan};LF-Show $script:LFLastScan}
      '3' {
        if(-not $script:LFLastScan){$script:LFLastScan=LF-Scan}
        LF-Repair $script:LFLastScan -SkipRescan
        if($script:LFRepairChanged){$script:LFLastScan=LF-Scan;LF-Show $script:LFLastScan}
      }
      '4' {if(-not $script:LFLastScan){$script:LFLastScan=LF-Scan};LF-Export $script:LFLastScan}
      '5' {& sfc.exe /verifyonly}
      '6' {LF-DeepMenu}
      '0' {}
      default {Write-Warning 'Lựa chọn không hợp lệ.'}
    }
    if($choice -ne '0'){[void](Read-Host 'Nhấn Enter để tiếp tục')}
  }while($choice -ne '0')
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
