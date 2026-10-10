#requires -Version 5.1
<#
LicenseFix v2.1.0-beta - Windows/Office license diagnostics and scoped remediation.
Preview build: test on a lab PC before performing repairs.
Independent project. Not affiliated with Microsoft or license.info.vn.
Repairs only specifically reviewed settings after successful backups and confirmation.
Never edits SPP data.dat/tokens.dat, history, or timestamps.
Product keys change only after separate, explicit confirmation by the user.
#>
[CmdletBinding()]
param([ValidateSet('Menu','Scan','Plan','Repair','Export','Deep')][string]$Mode='Menu')

$ErrorActionPreference = 'Stop'
$LFVersion = '2.1.0-beta'
$LFWindowsId = '55c92734-d682-4d71-983e-d6ec3f16059f'
$LFOfficeId = '0ff1ce15-a989-479d-af46-f275c6370663'
$LFBackups = Join-Path $env:ProgramData 'LicenseFix\Backups'
$LFReports = Join-Path $env:ProgramData 'LicenseFix\Reports'
$LFHosts = @('kms.digiboy.ir','kms.msguides.com','kms8.msguides.com','kms9.msguides.com')
$LFSuffixes = @('digiboy.ir','msguides.com','zpale.com','chinancce.com','03k.org','crsoo.com','loli.beer')
$LFLastScan = $null
$LFLastDeep = $null
$LFProductCache = $null

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
        if ([string]$p.ProductKeyChannel -match '(?i)VOLUME|KMSCLIENT|GVLK|MAK' -or
            [string]$p.Description -match '(?i)VOLUME[_:]|KMSCLIENT|MAK') { $kmsVolume = $true }
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
        LF-AddIssue $issues 'POL-001' 'Shared' 'REVIEW' 'Chính sách NoGenTicket=1 cần xác minh' $policy $false $policy 'NoGenTicket' '1'
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
    $script:LFProductCache = [pscustomobject]@{ At=Get-Date; Products=@($all); Office2010=@($office2010); Readable=($all.Count -gt 0) }
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
    Write-Host (" Office: {0} bản ghi cấp phép WMI" -f $Scan.OfficeDetected)
    Write-Host (" Kênh KMS/MAK trong WMI: {0}" -f $(if($Scan.KmsVolume){'Có'}else{'Chưa thấy trong phạm vi quét'}))
    Write-Host ' Trạng thái kích hoạt không xác nhận nguồn gốc pháp lý của key.' -ForegroundColor DarkGray
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
function LF-RepairBlockers($Scan) {
    $reasons = New-Object 'System.Collections.Generic.List[string]'
    if ($Scan.DomainJoinedOrUnknown) { [void]$reasons.Add('Máy thuộc domain hoặc chưa xác minh được trạng thái domain.') }
    if (-not $Scan.WindowsLicensed) { [void]$reasons.Add('Chưa xác minh được Windows đã kích hoạt.') }
    if (-not $Scan.OfficeSafe) { [void]$reasons.Add('Có sản phẩm Office cần xác minh giấy phép.') }
    if ($Scan.KmsVolume) { [void]$reasons.Add('Có giấy phép KMS/Volume có thể hợp lệ của tổ chức.') }
    return @($reasons.ToArray())
}
function LF-Repair($Scan,[switch]$SkipRescan) {
    $script:LFRepairChanged=$false
    LF-Title 'SAO LƯU VÀ SỬA REGISTRY'
    if (-not (LF-Admin)) { Write-Warning 'Hãy mở PowerShell với quyền Administrator để sửa lỗi.'; return }
    if (-not $Scan.RepairEligible) {
        Write-Warning 'Đã khóa sửa Registry. Chưa thay đổi dữ liệu.'
        foreach ($reason in @(LF-RepairBlockers $Scan)) { Write-Host (' - ' + $reason) -ForegroundColor Yellow }
        return
    }
    $fixes = @($Scan.Issues | Where-Object { $_.CanFix -and $_.RegistryPath -and $_.ValueName })
    if ($fixes.Count -eq 0) { Write-Host 'Không có giá trị Registry đủ điều kiện xử lý.'; return }
    foreach ($f in $fixes) { Write-Host ("SẼ XÓA {0}: {1} / {2} = {3}" -f $f.Id,$f.RegistryPath,$f.ValueName,$f.ExpectedValue) }
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
      [void]$items.Add((LF-DeepItem $i $titles[$i-1] 'NOT_CHECKED' 'Chưa có bằng chứng đầy đủ.' 'Chưa có phép kiểm đủ tin cậy; không sửa tự động.'))
    }
    $rows=$items.ToArray()
    try {
      $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
      $rows[0].Status='REVIEW';$rows[0].Evidence=([string]$os.Caption + '; chưa kiểm tra key OEM trong BIOS.')
      $rows[0].Action='Đối chiếu phiên bản Windows với chứng từ/OEM BIOS; không hiển thị product key.'
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
    $result = [pscustomobject]@{Version=$LFVersion;At=(Get-Date).ToString('o');Device=$env:COMPUTERNAME;Base=$base;Items=@($rows);DurationMs=[math]::Round($deepWatch.Elapsed.TotalMilliseconds,0)}
    $script:LFLastDeep = $result
    return $result
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
    Write-Host ' Chọn 2 để xem bằng chứng; chọn 3 để xem cách xử lý và lý do khóa sửa.' -ForegroundColor Cyan
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
    if ($it.Status -eq 'NOT_CHECKED') {
        Write-Host ' Chưa có phép kiểm đủ tin cậy cho mục này; không có thao tác sửa tự động.' -ForegroundColor Yellow
    }
}
function LF-InspectHosts {
    # Latin-1 maps each byte to itself, preserving existing UTF-8/ANSI bytes and line endings.
    # UTF-16 hosts files need manual review; rewriting one would change its encoding.
    $path = Join-Path $env:windir 'System32\drivers\etc\hosts'
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes -contains 0) { throw 'Tệp hosts có byte NUL/UTF-16; cần kiểm tra thủ công.' }
    $encoding = [Text.Encoding]::GetEncoding(28591)
    $content = $encoding.GetString($bytes)
    $targetNames = @('activation-v2.sls.microsoft.com','validation-v2.sls.microsoft.com')
    $safe = New-Object 'System.Collections.Generic.List[string]'
    $manual = New-Object 'System.Collections.Generic.List[string]'
    $fixed = New-Object Text.StringBuilder
    foreach ($match in [regex]::Matches($content, '([^\r\n]*)(\r\n|\n|\r|$)')) {
        if ($match.Length -eq 0) { continue }
        $line = $match.Groups[1].Value
        $body = ($line -split '#', 2)[0].Trim()
        $parts = @($body -split '\s+' | Where-Object { $_ })
        $remove = $false
        if ($parts.Count -ge 2) {
            $address = $null
            if ([Net.IPAddress]::TryParse($parts[0], [ref]$address)) {
                $names = @($parts[1..($parts.Count - 1)] | ForEach-Object { $_.TrimEnd('.').ToLowerInvariant() })
                $hits = @($names | Where-Object { $targetNames -contains $_ })
                if ($hits.Count -gt 0) {
                    if ($hits.Count -eq $names.Count) {
                        [void]$safe.Add($line)
                        $remove = $true
                    } else { [void]$manual.Add($line) }
                }
            }
        }
        if (-not $remove) { [void]$fixed.Append($match.Value) }
    }
    return [pscustomobject]@{
        Path=$path; Bytes=$bytes; SafeLines=@($safe.ToArray()); ManualLines=@($manual.ToArray());
        FixedBytes=$encoding.GetBytes($fixed.ToString())
    }
}
function LF-RepairHosts($Scan) {
    if (-not (LF-Admin)) { Write-Warning 'Cần quyền Administrator để sửa tệp hosts.'; return $false }
    if ($Scan.Base.DomainJoinedOrUnknown) {
        Write-Warning 'Máy thuộc domain hoặc chưa xác minh được domain. Hãy hỏi quản trị viên trước khi sửa hosts.'
        return $false
    }
    try { $review = LF-InspectHosts }
    catch { Write-Warning $_.Exception.Message; return $false }
    if ($review.ManualLines.Count) {
        Write-Warning 'Có dòng hosts chứa thêm tên miền khác; giữ nguyên để kiểm tra thủ công:'
        foreach ($line in $review.ManualLines) { Write-Host ('  ' + $line) -ForegroundColor Yellow }
    }
    if (-not $review.SafeLines.Count) { Write-Host 'Không có dòng hosts riêng cho máy chủ kích hoạt cần xử lý.'; return $false }
    Write-Host ' Các dòng dự kiến gỡ khỏi hosts:' -ForegroundColor Yellow
    foreach ($line in $review.SafeLines) { Write-Host ('  ' + $line) }
    if ((Read-Host 'Gõ HOSTS để sao lưu và gỡ đúng các dòng trên') -cne 'HOSTS') {
        Write-Host 'Đã hủy; tệp hosts không thay đổi.'
        return $false
    }
    try {
        $current = [IO.File]::ReadAllBytes($review.Path)
        $hash = [Security.Cryptography.SHA256]::Create()
        try {
            $before = [BitConverter]::ToString($hash.ComputeHash($review.Bytes))
            $now = [BitConverter]::ToString($hash.ComputeHash($current))
        } finally { $hash.Dispose() }
        if ($before -cne $now) { throw 'Tệp hosts đã thay đổi sau khi xem trước; hãy quét lại.' }
        $backup = Join-Path $LFBackups ('hosts-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,6))
        [void](New-Item -ItemType Directory -Path $backup -Force)
        $copy = Join-Path $backup 'hosts.before'
        Copy-Item -LiteralPath $review.Path -Destination $copy -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $copy)) { throw 'Sao lưu hosts thất bại; chưa sửa dữ liệu.' }
        if ((Get-FileHash -LiteralPath $copy -Algorithm SHA256).Hash -cne $before.Replace('-','')) {
            throw 'Bản sao lưu hosts không khớp dữ liệu gốc; chưa sửa dữ liệu.'
        }
        try {
            [IO.File]::WriteAllBytes($review.Path, $review.FixedBytes)
            $written = [IO.File]::ReadAllBytes($review.Path)
            $verifyHash = [Security.Cryptography.SHA256]::Create()
            try {
                $expected = [BitConverter]::ToString($verifyHash.ComputeHash($review.FixedBytes))
                $actual = [BitConverter]::ToString($verifyHash.ComputeHash($written))
            } finally { $verifyHash.Dispose() }
            if ($expected -cne $actual) { throw 'Không xác minh được dữ liệu hosts sau khi ghi.' }
        }
        catch {
            Copy-Item -LiteralPath $copy -Destination $review.Path -Force -ErrorAction SilentlyContinue
            throw
        }
        Write-Host ("Đã gỡ {0} dòng. Bản sao lưu: {1}" -f $review.SafeLines.Count,$copy) -ForegroundColor Green
        return $true
    } catch { Write-Warning ('Không sửa được hosts: ' + $_.Exception.Message); return $false }
}
function LF-DeepPlan($Scan) {
    LF-Title 'KẾ HOẠCH XỬ LÝ'
    $fixes = @($Scan.Base.Issues | Where-Object { $_.CanFix -and $_.RegistryPath -and $_.ValueName })
    Write-Host (" [R] Registry: {0} giá trị đủ điều kiện xử lý." -f $fixes.Count) -ForegroundColor $(if($fixes.Count){'Green'}else{'Yellow'})
    if ($fixes.Count) {
        foreach ($f in $fixes) { Write-Host ("     {0}: {1} / {2}" -f $f.Id,$f.RegistryPath,$f.ValueName) }
    } else {
        $blockers = @(LF-RepairBlockers $Scan.Base)
        if ($blockers.Count) { foreach ($reason in $blockers) { Write-Host ('     Khóa sửa: ' + $reason) -ForegroundColor Yellow } }
        else { Write-Host '     Không có cấu hình Registry bất thường thuộc phạm vi sửa đã hỗ trợ.' -ForegroundColor Gray }
    }
    try {
        $hosts = LF-InspectHosts
        if ($Scan.Base.DomainJoinedOrUnknown) {
            Write-Host ' [H] Hosts: khóa sửa vì máy thuộc domain hoặc chưa xác minh được domain.' -ForegroundColor Yellow
        } else {
            Write-Host (" [H] Hosts: {0} dòng có thể gỡ sau sao lưu và xác nhận." -f $hosts.SafeLines.Count) -ForegroundColor $(if($hosts.SafeLines.Count){'Green'}else{'Gray'})
        }
        if ($hosts.ManualLines.Count) { Write-Host ("     {0} dòng chứa tên miền khác cần kiểm tra thủ công." -f $hosts.ManualLines.Count) -ForegroundColor Yellow }
    } catch { Write-Host (' [H] Hosts: ' + $_.Exception.Message) -ForegroundColor Yellow }
    Write-Host ' [S] SFC /scannow: sửa tệp hệ thống khi có bằng chứng lỗi toàn vẹn.' -ForegroundColor White
    Write-Host ' [D] DISM /RestoreHealth: sửa kho thành phần Windows khi cần.' -ForegroundColor White
    Write-Host ' [K] Key chính hãng: xem key đã cài, nhập key Windows/Office phù hợp.' -ForegroundColor White
    Write-Host ''
    Write-Host ' Các mục cảnh báo, cần xem hoặc chưa quét:' -ForegroundColor Cyan
    foreach ($it in @($Scan.Items | Where-Object { $_.Status -ne 'PASS' })) {
        $label = switch ($it.Status) { 'WARN' {'CẢNH BÁO'} 'REVIEW' {'CẦN XEM'} default {'CHƯA QUÉT'} }
        Write-Host ("  {0,2}. {1,-11} {2}" -f $it.Id,$label,$it.Name) -ForegroundColor $(if($it.Status -eq 'WARN'){'Red'}else{'Yellow'})
        Write-Host ('      ' + $it.Action) -ForegroundColor Gray
    }
    Write-Host ' Xem bằng chứng tại Sửa lỗi chuyên sâu > 2. CẦN XEM/CHƯA QUÉT không tự chứng minh có lỗi.' -ForegroundColor Yellow
    Write-Host ' 19 nhóm là mục kiểm tra; chỉ những hành động đủ điều kiện mới có thể sửa tự động.' -ForegroundColor Yellow
}
function LF-DeepReport($Scan,[string]$Stage='scan'){
    New-Item -ItemType Directory -Force -Path $LFReports | Out-Null
    $path=Join-Path $LFReports ('deep-{0}-{1}-{2}.json' -f $Stage,(Get-Date -Format 'yyyyMMdd-HHmmss'),([guid]::NewGuid().ToString('N').Substring(0,6)))
    [pscustomobject]@{Version=$Scan.Version;At=$Scan.At;Device=$Scan.Device;Stage=$Stage;Checks=$Scan.Items;Findings=$Scan.Base.Issues;WindowsLicensed=$Scan.Base.WindowsLicensed;Channel=$Scan.Base.WindowsChannel} | ConvertTo-Json -Depth 9 | Out-File -LiteralPath $path -Encoding UTF8
    Write-Host ('Đã ghi báo cáo: '+$path) -ForegroundColor Green
}
function LF-DeepSystem([string]$Tool){
    if(-not (LF-Admin)){Write-Warning 'Cần chạy PowerShell với quyền Administrator.';return $false}
    if($Tool -eq 'SFC'){
      if((Read-Host 'Gõ SFC để xác nhận sfc /scannow (có thể sửa file hệ thống)') -cne 'SFC'){return $false}
      & sfc.exe /scannow | Out-Host
    }else{
      if((Read-Host 'Gõ DISM để xác nhận DISM /RestoreHealth (có thể sửa component store)') -cne 'DISM'){return $false}
      & dism.exe /Online /Cleanup-Image /RestoreHealth | Out-Host
    }
    Write-Host ('Exit code: '+$LASTEXITCODE)
    Write-Warning 'Sau sửa, phải kiểm tra lại trạng thái bản quyền và khởi động lại nếu hệ thống yêu cầu.'
    return $true
}
function LF-DeepAction($Scan) {
    LF-DeepPlan $Scan
    Write-Host ''
    $opt = (Read-Host 'Chọn R=Registry, H=Hosts, S=SFC, D=DISM, K=Key, 0=Hủy').ToUpperInvariant()
    switch ($opt) {
        'R' {
            $eligible = @($Scan.Base.Issues | Where-Object { $_.CanFix -and $_.RegistryPath -and $_.ValueName })
            if (-not $eligible.Count) {
                Write-Host 'Không có giá trị Registry đủ điều kiện sửa; xem lý do khóa ở kế hoạch trên.' -ForegroundColor Yellow
            } else {
                LF-DeepReport $Scan 'before'
                LF-Repair $Scan.Base -SkipRescan
                if ($script:LFRepairChanged) {
                    $script:LFLastDeep=$null; $script:LFLastScan=$null; $script:LFProductCache=$null
                    Write-Host 'Registry đã thay đổi. Hãy quét lại để có kết luận mới.' -ForegroundColor Yellow
                }
            }
        }
        'H' {
            if (LF-RepairHosts $Scan) {
                $script:LFLastDeep=$null; $script:LFLastScan=$null
                Write-Host 'Hosts đã thay đổi. Hãy quét lại để có kết luận mới.' -ForegroundColor Yellow
            }
        }
        'S' { if (LF-DeepSystem 'SFC') { $script:LFLastDeep=$null; $script:LFLastScan=$null } }
        'D' { if (LF-DeepSystem 'DISM') { $script:LFLastDeep=$null; $script:LFLastScan=$null } }
        'K' { LF-KeyMenu; $script:LFLastDeep=$null; $script:LFLastScan=$null }
        '0' { Write-Host 'Đã hủy.' }
        default { Write-Warning 'Lựa chọn không hợp lệ.' }
    }
}
function LF-DeepMenu {
  $scan=$script:LFLastDeep
  do {
    Clear-Host
    LF-Title 'SỬA LỖI CHUYÊN SÂU'
    Write-Host ' 1. Quét và xem tổng quan'
    Write-Host ' 2. Xem chi tiết theo số mục'
    Write-Host ' 3. Xem kế hoạch xử lý và lý do khóa sửa'
    Write-Host ' 4. Thực hiện sửa lỗi được hỗ trợ'
    Write-Host ' 5. Xuất báo cáo JSON'
    Write-Host ' 0. Quay về'
    $choice=Read-Host 'Chọn'
    switch($choice) {
      '1' {Clear-Host;$scan=LF-DeepInspect;LF-DeepDisplay $scan}
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
        LF-DeepPlan $scan
      }
      '4' {
        if(-not $scan){$scan=LF-DeepInspect}
        LF-DeepAction $scan
        $scan=$script:LFLastDeep
      }
      '5' {if(-not $scan){$scan=LF-DeepInspect};LF-DeepReport $scan 'manual'}
      '0' {}
      default {Write-Warning 'Lựa chọn không hợp lệ.'}
    }
    if($choice -ne '0'){[void](Read-Host 'Nhấn Enter để tiếp tục')}
  }while($choice -ne '0')
}
function LF-LicenseState([int]$Code) {
    switch ($Code) {
        0 { return 'Chưa kích hoạt' }
        1 { return 'Đã kích hoạt (trạng thái kỹ thuật)' }
        2 { return 'Thời gian ân hạn ban đầu' }
        3 { return 'Thời gian ân hạn bổ sung' }
        4 { return 'Cần xác minh tính chính hãng' }
        5 { return 'Thông báo cần kích hoạt' }
        6 { return 'Thời gian ân hạn mở rộng' }
        default { return ('Chưa xác định (' + $Code + ')') }
    }
}
function LF-IsVolumeProduct($Product) {
    return ([string]$Product.ProductKeyChannel -match '(?i)VOLUME|KMSCLIENT|GVLK|MAK' -or
            [string]$Product.Description -match '(?i)VOLUME[_:]|KMSCLIENT|MAK')
}
function LF-UpdateChannelName([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value)) { return 'Chưa đọc được' }
    $id = [regex]::Match($Value.ToLowerInvariant(), '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}').Value
    switch ($id) {
        '492350f6-3a01-4f97-b9c0-c7c6ddf67d60' { return 'Current Channel' }
        '55336b82-a18d-4dd6-b5f6-9e5095c314a6' { return 'Monthly Enterprise Channel' }
        '7ffbc6bf-bc32-4f92-8982-f9dd17fd3114' { return 'Semi-Annual Enterprise Channel' }
        default { if ($id) { return ('Chưa đặt tên (' + $id + ')') }; return 'Chưa xác định' }
    }
}
function LF-GetKeyInventory([switch]$ForceRefresh) {
    $products = @()
    $wmiReadable = $false
    $office2010 = @()
    $cached = $script:LFProductCache
    if (-not $ForceRefresh -and $cached -and $cached.Readable -and ((Get-Date) - $cached.At).TotalMinutes -lt 5) {
        $products = @($cached.Products)
        $office2010 = @($cached.Office2010)
        $wmiReadable = $true
        Write-Host 'Đang dùng dữ liệu cấp phép vừa quét; chọn 1 để đọc lại từ Windows.' -ForegroundColor DarkGray
    } else {
        Write-Host 'Đang đọc WMI cấp phép; bước này có thể mất vài chục giây...' -ForegroundColor Cyan
        try {
            $filter = "ApplicationID='$LFWindowsId' OR ApplicationID='$LFOfficeId'"
            $products = @(Get-CimInstance -ClassName SoftwareLicensingProduct -Filter $filter -ErrorAction Stop |
                Where-Object { $_.PartialProductKey -and $_.ApplicationID -in @($LFWindowsId,$LFOfficeId) })
            $wmiReadable = $true
        } catch {
            try {
                $products = @(Get-CimInstance -ClassName SoftwareLicensingProduct -ErrorAction Stop |
                    Where-Object { $_.PartialProductKey -and $_.ApplicationID -in @($LFWindowsId,$LFOfficeId) })
                $wmiReadable = $true
            } catch {}
        }
        try { $office2010 = @(Get-CimInstance -ClassName OfficeSoftwareProtectionProduct -ErrorAction Stop | Where-Object PartialProductKey) }
        catch {}
        $script:LFProductCache = [pscustomobject]@{ At=Get-Date; Products=@($products); Office2010=@($office2010); Readable=$wmiReadable }
    }
    $windows = @($products | Where-Object { $_.ApplicationID -eq $LFWindowsId } | Sort-Object LicenseStatus -Descending)
    $office = @($products | Where-Object { $_.ApplicationID -eq $LFOfficeId } | Sort-Object LicenseStatus -Descending)
    $office += $office2010
    $caption = 'Chưa đọc được phiên bản Windows'
    try { $caption = [string](Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch {}
    $domainUnknown = $true
    try { $domainUnknown = [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain } catch {}
    $oemTail = 'Không thấy hoặc không đọc được'
    try {
        $oemKey = [string](Get-CimInstance -ClassName SoftwareLicensingService -Property OA3xOriginalProductKey -ErrorAction Stop).OA3xOriginalProductKey
        if ($oemKey.Length -ge 5) { $oemTail = ('*****-' + $oemKey.Substring($oemKey.Length - 5)) }
        $oemKey = $null
    } catch {}
    $invPath = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Inventory\Office\16.0'
    $cfgPath = 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration'
    $officeInv = $null; $officeCfg = $null
    try { $officeInv = Get-ItemProperty -LiteralPath $invPath -ErrorAction Stop } catch {}
    try { $officeCfg = Get-ItemProperty -LiteralPath $cfgPath -ErrorAction Stop } catch {}
    $productIds = @([string]$officeInv.OfficeProductReleaseIds -split '\s*,\s*' | Where-Object { $_ })
    $installed = New-Object 'System.Collections.Generic.List[string]'
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                       'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        try {
            foreach ($item in @(Get-ItemProperty -Path ($root + '\*') -ErrorAction Stop)) {
                if ([string]$item.DisplayName -match '(?i)^Microsoft (Office|365|Visio|Project)\b' -and
                    -not $installed.Contains([string]$item.DisplayName)) { [void]$installed.Add([string]$item.DisplayName) }
            }
        } catch {}
    }
    $installedVolume = @($productIds | Where-Object { $_ -match '(?i)Volume' }).Count -gt 0
    $hasVolume = ($installedVolume -or
                  @($office | Where-Object { LF-IsVolumeProduct $_ }).Count -gt 0)
    $hasSubscription = @($productIds | Where-Object { $_ -match '(?i)O365|M365|Microsoft365' }).Count -gt 0
    $hasRetail = @($productIds | Where-Object { $_ -match '(?i)Retail' }).Count -gt 0
    $officeType = if ($installedVolume -and ($hasSubscription -or $hasRetail)) { 'Hỗn hợp' }
                  elseif ($installedVolume) { 'Volume (tổ chức)' }
                  elseif ($hasSubscription) { 'Microsoft 365 / thuê bao' }
                  elseif ($hasRetail) { 'Retail' }
                  elseif ($hasVolume) { 'WMI thấy Volume; chưa xác nhận đang cài' }
                  else { 'Chưa xác định' }
    return [pscustomobject]@{
        WindowsName=$caption; Windows=$windows; Office=$office; WmiReadable=$wmiReadable;
        DomainJoinedOrUnknown=$domainUnknown; OemBiosTail=$oemTail;
        WindowsVolume=(@($windows | Where-Object { LF-IsVolumeProduct $_ }).Count -gt 0);
        OfficeProductIds=$productIds; OfficeVersion=[string]$officeInv.OfficePackageVersion;
        OfficeArchitecture=[string]$officeCfg.Platform; OfficeUpdateChannel=(LF-UpdateChannelName ([string]$officeCfg.UpdateChannel));
        OfficeType=$officeType; OfficeVolume=$hasVolume; InstalledOfficeVolume=$installedVolume;
        InstalledOffice=@($installed.ToArray())
    }
}
function LF-ShowKeyInventory($Inventory) {
    LF-Title 'KEY ĐÃ CÀI VÀ CÁCH KÍCH HOẠT'
    Write-Host (' Windows: ' + $Inventory.WindowsName) -ForegroundColor Cyan
    if (-not $Inventory.WmiReadable) { Write-Warning 'Không đọc được WMI cấp phép; kết quả dưới đây chưa đầy đủ.' }
    if (-not @($Inventory.Windows).Count) { Write-Host '  Chưa đọc được bản ghi key Windows đang cài.' -ForegroundColor Yellow }
    foreach ($p in @($Inventory.Windows)) {
        Write-Host ("  {0} | Key *****-{1} | {2}" -f $p.Name,$p.PartialProductKey,(LF-LicenseState $p.LicenseStatus))
        Write-Host ("  Kênh: {0}" -f $(if($p.ProductKeyChannel){$p.ProductKeyChannel}else{'Chưa rõ'})) -ForegroundColor Gray
        if ($p.KeyManagementServiceMachine) { Write-Host ("  Máy chủ KMS: {0} (cần đối chiếu với quản trị viên)" -f $p.KeyManagementServiceMachine) -ForegroundColor Yellow }
    }
    Write-Host ('  Key OEM nhúng BIOS: ' + $Inventory.OemBiosTail + ' (có thể khác key đang dùng)') -ForegroundColor Gray
    Write-Host ''
    Write-Host (' Office: ' + $Inventory.OfficeType) -ForegroundColor Cyan
    if (@($Inventory.OfficeProductIds).Count) { Write-Host ('  Sản phẩm cài đặt: ' + ($Inventory.OfficeProductIds -join ', ')) }
    elseif (@($Inventory.InstalledOffice).Count) { Write-Host ('  Mục cài đặt tham khảo: ' + (($Inventory.InstalledOffice | Select-Object -First 5) -join ', ')) }
    else { Write-Host '  Chưa đọc được thông tin Office đã cài.' -ForegroundColor Yellow }
    Write-Host ("  Phiên bản: {0} | Kiến trúc: {1}" -f $(if($Inventory.OfficeVersion){$Inventory.OfficeVersion}else{'Chưa rõ'}),$(if($Inventory.OfficeArchitecture){$Inventory.OfficeArchitecture}else{'Chưa rõ'}))
    Write-Host ('  Kênh cập nhật: ' + $Inventory.OfficeUpdateChannel + ' (khác kiểu giấy phép)')
    if (@($Inventory.Office).Count) { Write-Host '  Bản ghi cấp phép WMI (có thể gồm sản phẩm cũ còn lưu):' -ForegroundColor Gray }
    foreach ($p in @($Inventory.Office)) {
        Write-Host ("  {0} | Key *****-{1} | {2}" -f $p.Name,$p.PartialProductKey,(LF-LicenseState $p.LicenseStatus))
        Write-Host ("  Kênh cấp phép: {0}" -f $(if($p.ProductKeyChannel){$p.ProductKeyChannel}else{'Chưa rõ'})) -ForegroundColor Gray
    }
    if ($Inventory.OfficeType -match 'Microsoft 365' -or ($Inventory.OfficeProductIds -join ',') -match '(?i)O365|M365') {
        Write-Host '  Microsoft 365 dùng tài khoản/thuê bao; WMI có thể không thể hiện trạng thái vNext.' -ForegroundColor Yellow
    }
    Write-Host ''
    Write-Host (" Kênh KMS/MAK phát hiện: {0}." -f $(if($Inventory.WindowsVolume -or $Inventory.OfficeVolume){'Có'}else{'Chưa thấy'})) -ForegroundColor Yellow
    Write-Host ' KMS/MAK có thể là giấy phép hợp lệ của tổ chức. Key đã kích hoạt cũng không chứng minh nguồn gốc mua.' -ForegroundColor Yellow
    Write-Host ' Chỉ hiển thị 5 ký tự cuối; chương trình không khôi phục toàn bộ key từ máy.' -ForegroundColor DarkGray
}
function LF-ReadOwnedKey {
    $secret = Read-Host 'Nhập key bạn sở hữu (ẩn ký tự; Enter để hủy)' -AsSecureString
    if (-not $secret -or $secret.Length -eq 0) { return $null }
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
    try { $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer).ToUpperInvariant() }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $secret.Dispose() }
    $compact = $value.Replace('-','')
    $value = $null
    if ($compact -cnotmatch '^[A-Z0-9]{25}$') { Write-Warning 'Key cần 25 ký tự chữ/số; không gửi key cho hệ thống.'; return $null }
    return ([regex]::Replace($compact,'(.{5})(?=.)','$1-'))
}
function LF-InstallWindowsKey($Inventory) {
    if (-not (LF-Admin)) { Write-Warning 'Cần quyền Administrator để nhập key Windows.'; return $false }
    if ($Inventory.DomainJoinedOrUnknown -or $Inventory.WindowsVolume) {
        Write-Warning 'Máy thuộc tổ chức, chưa xác minh domain hoặc đang dùng Volume; hãy hỏi quản trị viên trước khi thay key Windows.'
        return $false
    }
    Write-Host ('Phiên bản hiện tại: ' + $Inventory.WindowsName)
    Write-Warning 'Key mới có thể thay key đang cài. Không thể tự hoàn tác nếu bạn không giữ key cũ.'
    Write-Host 'Windows sẽ kiểm tra key có phù hợp phiên bản; kích hoạt trực tuyến là bước riêng.'
    if ((Read-Host 'Gõ WINDOWS để tiếp tục') -cne 'WINDOWS') { return $false }
    $key = LF-ReadOwnedKey
    if (-not $key) { return $false }
    try {
        $service = Get-CimInstance -ClassName SoftwareLicensingService -ErrorAction Stop
        $result = Invoke-CimMethod -InputObject $service -MethodName InstallProductKey -Arguments @{ProductKey=$key} -ErrorAction Stop
        $returnCode = $result.ReturnValue
    } catch {
        Write-Warning ('Không cài được key Windows. Mã hệ thống: ' + ('0x{0:X8}' -f $_.Exception.HResult))
        return $false
    } finally { $key = $null }
    if ($returnCode -ne 0) { Write-Warning ('Windows từ chối key; mã kết quả: ' + $returnCode); return $false }
    Write-Host 'Windows đã nhận key. Điều này chưa xác nhận key đã kích hoạt hoặc nguồn gốc bản quyền.' -ForegroundColor Green
    if ((Read-Host 'Gõ KICHHOAT để thử kích hoạt trực tuyến, hoặc Enter để bỏ qua') -ceq 'KICHHOAT') {
        & (Join-Path $env:SystemRoot 'System32\cscript.exe') //Nologo (Join-Path $env:SystemRoot 'System32\slmgr.vbs') /ato | Out-Host
        Write-Host ('Mã thoát kích hoạt: ' + $LASTEXITCODE)
    }
    return $true
}
function LF-FindOfficeScript([string]$Name) {
    $roots = @($env:ProgramFiles,[Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) | Where-Object { $_ } | Select-Object -Unique
    $found = New-Object 'System.Collections.Generic.List[string]'
    foreach ($root in $roots) {
        foreach ($folder in @('Microsoft Office\root\Office16','Microsoft Office\Office16','Microsoft Office\Office15','Microsoft Office\Office14')) {
            $path = Join-Path (Join-Path $root $folder) $Name
            if (Test-Path -LiteralPath $path -PathType Leaf) { [void]$found.Add($path) }
        }
    }
    return @($found.ToArray())
}
function LF-InstallOfficeVolumeKey($Inventory) {
    if (-not (LF-Admin)) { Write-Warning 'Cần quyền Administrator để nhập key Office Volume.'; return $false }
    if (-not $Inventory.InstalledOfficeVolume) {
        Write-Warning 'Chưa xác nhận bản Office Volume đang cài. Bản ghi WMI có thể thuộc Office cũ; không nhập key qua ospp.vbs khi chỉ có bằng chứng này.'
        return $false
    }
    $scripts = @(LF-FindOfficeScript 'ospp.vbs')
    if (-not $scripts.Count) { Write-Warning 'Không tìm thấy ospp.vbs của Office Volume.'; return $false }
    Write-Host ('Office nhận diện: ' + (($Inventory.OfficeProductIds | Select-Object -First 5) -join ', '))
    for ($i=0; $i -lt $scripts.Count; $i++) { Write-Host (" {0}. {1}" -f ($i+1),$scripts[$i]) }
    $index = 1
    if ($scripts.Count -gt 1 -and -not [int]::TryParse((Read-Host 'Chọn đường dẫn ospp.vbs'),[ref]$index)) { return $false }
    if ($index -lt 1 -or $index -gt $scripts.Count) { Write-Warning 'Lựa chọn không hợp lệ.'; return $false }
    $ospp = $scripts[$index-1]
    Write-Warning 'Chỉ dùng key MAK/Volume do tổ chức cấp. Lệnh ospp.vbs có thể để lộ key tạm thời trong dòng lệnh của tiến trình.'
    Write-Warning 'Key mới có thể thay key Office đang cài; không thể tự hoàn tác nếu thiếu key cũ.'
    if ((Read-Host 'Gõ OFFICE để tiếp tục') -cne 'OFFICE') { return $false }
    $key = LF-ReadOwnedKey
    if (-not $key) { return $false }
    try {
        $argument = '/inpkey:' + $key
        $output = @(& (Join-Path $env:SystemRoot 'System32\cscript.exe') //Nologo $ospp $argument 2>&1)
        $exitCode = $LASTEXITCODE
        $errorCode = [regex]::Match(($output -join ' '), '(?i)ERROR\s+CODE\s*:\s*(0x[0-9a-f]{8})').Groups[1].Value
    } catch {
        Write-Warning 'Không chạy được công cụ nhập key Office. Không hiển thị lỗi thô để tránh lộ key.'
        return $false
    } finally { $key=$null; $argument=$null; $output=$null }
    if ($exitCode -ne 0 -or $errorCode) {
        Write-Warning ("Office chưa xác nhận đã nhận key. Mã thoát: $exitCode; mã lỗi: $errorCode")
        return $false
    }
    Write-Host 'Đã gửi key tới ospp.vbs. Hãy kiểm tra lại trạng thái; nhập key chưa đồng nghĩa kích hoạt thành công.' -ForegroundColor Green
    if ((Read-Host 'Gõ KICHHOAT để thử kích hoạt Office Volume, hoặc Enter để bỏ qua') -ceq 'KICHHOAT') {
        & (Join-Path $env:SystemRoot 'System32\cscript.exe') //Nologo $ospp /act | Out-Host
        Write-Host ('Mã thoát kích hoạt: ' + $LASTEXITCODE)
    }
    return $true
}
function LF-OfficeKeyGuide($Inventory) {
    LF-Title 'CHỌN CÁCH KÍCH HOẠT OFFICE'
    Write-Host ('Loại Office nhận diện: ' + $Inventory.OfficeType)
    Write-Host 'Microsoft 365: đăng nhập tài khoản có thuê bao trong Word/Excel > File > Account.'
    Write-Host 'Office Retail mới mua: đổi key tại https://www.office.com/setup rồi đăng nhập cùng tài khoản.'
    Write-Host 'Office đã đổi key trước đây: đăng nhập tài khoản đã liên kết, thường không cần nhập lại key.'
    Write-Host 'Office Volume/MAK: chỉ dùng key do tổ chức cấp; liên hệ quản trị viên nếu dùng KMS/ADBA.'
    Write-Host 'Kiến trúc 32/64-bit và kênh cập nhật không quyết định loại key cần mua.' -ForegroundColor Yellow
}
function LF-ShowVNextStatus {
    $scripts = @(LF-FindOfficeScript 'vnextdiag.ps1' | Where-Object { $_ -match 'Office16' })
    if (-not $scripts.Count) { Write-Host 'Không thấy vnextdiag.ps1; xem trạng thái trong Word/Excel > File > Account.' -ForegroundColor Yellow; return }
    try {
        $runner = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
        $lines = @(& $runner -NoProfile -NonInteractive -File $scripts[0] -action list 2>&1 | ForEach-Object { [string]$_ })
        if ($LASTEXITCODE -ne 0) { throw 'vnextdiag failed' }
        $shown = 0; $section = ''
        foreach ($line in $lines) {
            if ($line -match '(?i)vNext licenses found') { $section='user'; continue }
            if ($line -match '(?i)Device licenses found') { $section='device'; continue }
            if ($line -match '(?i)^\s*([A-Za-z0-9]+)\s*=\s*vNext\s*$') {
                Write-Host ('Sản phẩm dùng cơ chế vNext: ' + $matches[1])
                $shown++
            }
            elseif ($line -match '(?i)^\s*(?:License State|State)\s*[:=]\s*(Licensed|Unlicensed|Expired|Grace|Notification)\b') {
                Write-Host ('Trạng thái vNext: ' + $matches[1]); $shown++
            }
            elseif ($section -eq 'user' -and $line -match '(?i)No licenses found') {
                Write-Host 'Không thấy giấy phép thuê bao vNext trong kết quả.' -ForegroundColor Yellow; $shown++
            }
        }
        if (-not $shown) { Write-Host 'Không trích xuất được trạng thái đáng tin cậy.' -ForegroundColor Yellow }
        Write-Host 'Để xác nhận tài khoản và thuê bao, xem Word/Excel > File > Account.' -ForegroundColor Gray
    } catch { Write-Warning 'Không đọc được trạng thái vNext; xem Word/Excel > File > Account.' }
}
function LF-KeyMenu {
    Write-Host 'Đang đọc key và Office đã cài (không quét sâu)...' -ForegroundColor Cyan
    $inventory = LF-GetKeyInventory
    do {
        Clear-Host
        LF-ShowKeyInventory $inventory
        Write-Host ''
        Write-Host ' 1. Đọc lại thông tin key và Office'
        Write-Host ' 2. Nhập key Windows chính hãng'
        Write-Host ' 3. Nhập key Office Volume/MAK của tổ chức'
        Write-Host ' 4. Hướng dẫn Office Retail / Microsoft 365'
        Write-Host ' 5. Xem trạng thái Microsoft 365 bằng vnextdiag'
        Write-Host ' 6. Quét dấu hiệu can thiệp (chuyên sâu, có thể chậm)'
        Write-Host ' 0. Quay về'
        $choice = Read-Host 'Chọn'
        switch ($choice) {
            '1' { $inventory = LF-GetKeyInventory -ForceRefresh }
            '2' { if (LF-InstallWindowsKey $inventory) { $inventory = LF-GetKeyInventory -ForceRefresh } }
            '3' { if (LF-InstallOfficeVolumeKey $inventory) { $inventory = LF-GetKeyInventory -ForceRefresh } }
            '4' { LF-OfficeKeyGuide $inventory }
            '5' { LF-ShowVNextStatus }
            '6' { $deep = LF-DeepInspect; LF-DeepDisplay $deep; Write-Host 'Dấu hiệu kỹ thuật không kết luận key mua hợp pháp hay crack.' -ForegroundColor Yellow }
            '0' {}
            default { Write-Warning 'Lựa chọn không hợp lệ.' }
        }
        if ($choice -ne '0') { [void](Read-Host 'Nhấn Enter để tiếp tục') }
    } while ($choice -ne '0')
}
function LF-Menu {
  do {
    Clear-Host
    LF-Title 'MENU CHÍNH'
    Write-Host ' 1. Kiểm tra bản quyền Windows / Office'
    Write-Host ' 2. Xem kế hoạch sửa và lý do bị khóa'
    Write-Host ' 3. Thực hiện sửa lỗi được hỗ trợ'
    Write-Host ' 4. Xuất báo cáo JSON'
    Write-Host ' 5. Kiểm tra SFC (chỉ đọc)'
    Write-Host ' 6. Sửa lỗi chuyên sâu'
    Write-Host ' 7. Xem key đang cài / nhập key chính hãng'
    Write-Host ' 0. Thoát'
    $choice=Read-Host 'Chọn'
    switch($choice) {
      '1' {$script:LFLastScan=LF-Scan;LF-Show $script:LFLastScan}
      '2' {
        if (-not $script:LFLastDeep) { $script:LFLastDeep=LF-DeepInspect }
        LF-DeepPlan $script:LFLastDeep
      }
      '3' {
        if (-not $script:LFLastDeep) { $script:LFLastDeep=LF-DeepInspect }
        LF-DeepAction $script:LFLastDeep
      }
      '4' {if(-not $script:LFLastScan){$script:LFLastScan=LF-Scan};LF-Export $script:LFLastScan}
      '5' {& sfc.exe /verifyonly}
      '6' {LF-DeepMenu}
      '7' {LF-KeyMenu}
      '0' {}
      default {Write-Warning 'Lựa chọn không hợp lệ.'}
    }
    if($choice -ne '0'){[void](Read-Host 'Nhấn Enter để quay về menu chính')}
  }while($choice -ne '0')
}
if (-not $env:SystemRoot) { throw 'Windows only.' }
switch ($Mode) {
    'Scan'   { LF-Show (LF-Scan) }
    'Plan'   { LF-DeepPlan (LF-DeepInspect) }
    'Repair' { LF-DeepAction (LF-DeepInspect) }
    'Export' { $scan=LF-Scan; LF-Export $scan }
    'Deep' { LF-DeepMenu }
    default  { LF-Menu }
}
