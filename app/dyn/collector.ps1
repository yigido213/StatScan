# StatScan dinamik analiz toplayicisi
# Windows Sandbox ICINDE calisir; ana sistemde asla calistirilmaz.
# Yalnizca Windows PowerShell 5.1 ozellikleri kullanilir. Dosya bilerek yalnizca ASCII karakter icerir.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$InDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Base   = Split-Path -Parent $InDir
$OutDir = Join-Path $Base 'out'
$RunDir = 'C:\ssrun'
$Utf8   = New-Object System.Text.UTF8Encoding($false)
$ScriptStart     = Get-Date
$script:Errors = New-Object System.Collections.ArrayList
$script:Notes  = New-Object System.Collections.ArrayList

function Add-Err([string]$where, $e) {
    if ($script:Errors.Count -ge 60) { return }
    $m = ''
    try { if ($e -is [System.Management.Automation.ErrorRecord]) { $m = $e.Exception.Message } else { $m = [string]$e } } catch { $m = 'hata' }
    [void]$script:Errors.Add(($where + ': ' + $m))
}
function Add-Note([string]$m) { if ($script:Notes.Count -lt 60) { [void]$script:Notes.Add($m) } }
function Iso($d) { try { if ($d -is [datetime]) { return $d.ToUniversalTime().ToString('o') } } catch { } return $null }
function Write-OutText([string]$name, [string]$text) {
    [System.IO.File]::WriteAllText((Join-Path $OutDir $name), $text, $Utf8)
}
function Set-Status([string]$phase, [int]$elapsed, [int]$total) {
    try {
        $o = @{ phase = $phase; t = [int]((Get-Date) - $ScriptStart).TotalSeconds; elapsed = $elapsed; total = $total }
        Write-OutText 'status.json' (ConvertTo-Json -InputObject $o -Compress)
    } catch { }
}
function Get-Sha256Stream([string]$path) {
    $fs = $null; $sha = $null
    try {
        $fs = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $h = $sha.ComputeHash($fs)
        return (($h | ForEach-Object { $_.ToString('x2') }) -join '')
    } catch { return $null } finally { if ($fs) { $fs.Dispose() }; if ($sha) { $sha.Dispose() } }
}
function Get-Head([string]$path, [int]$n) {
    $fs = $null
    try {
        $fs = New-Object System.IO.FileStream($path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $buf = New-Object byte[] $n
        $r = $fs.Read($buf, 0, $n)
        if ($r -lt $n) { $b2 = New-Object byte[] $r; [Array]::Copy($buf, $b2, $r); return $b2 }
        return $buf
    } catch { return (New-Object byte[] 0) } finally { if ($fs) { $fs.Dispose() } }
}

try { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null } catch { }
try { Write-OutText 'started.flag' 'ok' } catch { }

$Cfg = $null
try { $Cfg = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $InDir 'run.json') | ConvertFrom-Json } catch { }
if (-not $Cfg) {
    try { Write-OutText 'result.json' (ConvertTo-Json -InputObject @{ schema = 1; fatal = 'run.json okunamadi' } -Compress); Write-OutText 'done.flag' 'ok' } catch { }
    shutdown.exe /s /t 3 /f
    exit 1
}

$Plan = [int]$Cfg.durationSec
if ($Plan -lt 5) { $Plan = 5 }
$SampleName = [System.IO.Path]::GetFileName([string]$Cfg.sampleName)
$SamplePath = Join-Path $RunDir $SampleName
$JavaExe = 'C:\Users\WDAGUtilityAccount\Desktop\jre\bin\java.exe'

$result = [ordered]@{
    schema = 1; collectorVersion = '1.0'; jobId = [string]$Cfg.jobId; collectorPid = $PID
    startedAt = (Iso (Get-Date)); plannedSec = $Plan
}

try {
    Set-Status 'prepare' 0 $Plan

    # --- Kayit/ayar: Defender ornek gondermesin (sizinti onlemi), istenirse gercek zamanli korumayi kapat ---
    try { Set-MpPreference -SubmitSamplesConsent 2 -MAPSReporting 0 -ErrorAction Stop } catch { Add-Err 'defender-privacy' $_ }
    if ([string]$Cfg.defender -eq 'disable') {
        try { Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true -DisableScriptScanning $true -ErrorAction Stop } catch { Add-Err 'defender-off' $_; Add-Note 'Defender kapatilamadi (Tamper Protection olabilir).' }
    }

    # --- Surec olusturma denetimi (komut satiri dahil, kisa omurlu surecleri de yakalar) ---
    try {
        & auditpol.exe /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null
        & reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
    } catch { Add-Err 'audit' $_ }

    # --- DNS istemci gunlugu ---
    try {
        & wevtutil.exe sl "Microsoft-Windows-DNS-Client/Operational" /e:true | Out-Null
        & wevtutil.exe cl "Microsoft-Windows-DNS-Client/Operational" | Out-Null
    } catch { Add-Err 'dns-log' $_ }

    # --- Ag etkinse yerel agi engelle (en iyi caba; guvenlik siniri degil) ---
    $fwBlock = $false
    if ([string]$Cfg.networking -ne 'Disable' -and $Cfg.firewallLanBlock -eq $true) {
        try {
            $priv = @('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '100.64.0.0/10', '224.0.0.0/4', 'fe80::/10', 'fc00::/7')
            New-NetFirewallRule -DisplayName 'ss-lan-block-tcp' -Direction Outbound -Action Block -Protocol TCP -RemoteAddress $priv -RemotePort @('1-52', '54-65535') | Out-Null
            New-NetFirewallRule -DisplayName 'ss-lan-block-udp' -Direction Outbound -Action Block -Protocol UDP -RemoteAddress $priv -RemotePort @('1-52', '54-65535') | Out-Null
            New-NetFirewallRule -DisplayName 'ss-lan-block-icmp' -Direction Outbound -Action Block -Protocol ICMPv4 -RemoteAddress $priv | Out-Null
            $fwBlock = $true
        } catch { Add-Err 'firewall' $_ }
    }

    # --- Calistirma klasorune ornegi kopyala ---
    New-Item -ItemType Directory -Force -Path $RunDir | Out-Null
    Copy-Item -LiteralPath (Join-Path $InDir 'sample.dat') -Destination $SamplePath -Force
    $sha0 = Get-Sha256Stream $SamplePath
    Start-Sleep -Milliseconds 1500
    $existsBefore = Test-Path -LiteralPath $SamplePath

    # --- Tuzak veri (stealer/clipper tespiti): sahte kimlik dosyalari, denetim kurallari, pano ve fare ---
    $baitOn = ($Cfg.bait -eq $true)
    $baitFiles = New-Object System.Collections.ArrayList
    $baitAuditOk = $false
    $clipPlan = New-Object System.Collections.ArrayList
    $clipLog = New-Object System.Collections.ArrayList
    $clipPending = $false
    $mouseOk = $false
    $rng = New-Object System.Random 7
    if ($baitOn) {
        try {
            $uh = 'C:\Users\WDAGUtilityAccount'
            function New-RandBytes([int]$n, [string]$magic) {
                $b = New-Object byte[] $n
                $rng.NextBytes($b)
                if ($magic) { $m = [System.Text.Encoding]::ASCII.GetBytes($magic); [Array]::Copy($m, 0, $b, 0, [Math]::Min($m.Length, $n)) }
                return ,$b
            }
            function New-Bait([string]$path, $bytes, [string]$kind) {
                try {
                    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path) | Out-Null
                    [System.IO.File]::WriteAllBytes($path, [byte[]]$bytes)
                    [void]$baitFiles.Add(@{ path = $path; kind = $kind })
                } catch { Add-Err 'bait-file' $_ }
            }
            function New-Part([int]$n) {
                $cs = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-'
                $o = New-Object System.Text.StringBuilder
                for ($i = 0; $i -lt $n; $i++) { [void]$o.Append($cs[$rng.Next(0, $cs.Length)]) }
                return $o.ToString()
            }
            function New-Text([string]$t) { return ,([System.Text.Encoding]::UTF8.GetBytes($t)) }
            $tok = 'MT' + (New-Part 22) + '.' + (New-Part 6) + '.' + (New-Part 27)
            $b64key = [Convert]::ToBase64String((New-RandBytes 150 'DPAPI'))
            $lsJson = '{"os_crypt":{"encrypted_key":"' + $b64key + '"}}'
            # tarayicilar
            foreach ($br in @('Google\Chrome', 'Microsoft\Edge', 'BraveSoftware\Brave-Browser')) {
                $bb = Join-Path $uh ('AppData\Local\' + $br + '\User Data')
                New-Bait (Join-Path $bb 'Default\Login Data') (New-RandBytes 40960 'SQLite format 3') 'browser'
                New-Bait (Join-Path $bb 'Default\Network\Cookies') (New-RandBytes 40960 'SQLite format 3') 'browser'
                New-Bait (Join-Path $bb 'Default\Web Data') (New-RandBytes 20480 'SQLite format 3') 'browser'
                New-Bait (Join-Path $bb 'Local State') (New-Text $lsJson) 'browser'
            }
            $ff = Join-Path $uh 'AppData\Roaming\Mozilla\Firefox\Profiles\ss01.default-release'
            New-Bait (Join-Path $ff 'logins.json') (New-Text ('{"nextId":2,"logins":[{"id":1,"hostname":"https://example.com","encryptedUsername":"' + (New-Part 40) + '","encryptedPassword":"' + (New-Part 60) + '"}]}')) 'browser'
            New-Bait (Join-Path $ff 'key4.db') (New-RandBytes 32768 'SQLite format 3') 'browser'
            # oturum belirteclari
            New-Bait (Join-Path $uh 'AppData\Roaming\discord\Local Storage\leveldb\000005.ldb') (New-Text ('....token","' + $tok + '"...')) 'token'
            New-Bait (Join-Path $uh 'AppData\Roaming\discord\Local State') (New-Text $lsJson) 'token'
            New-Bait (Join-Path $uh 'AppData\Roaming\Telegram Desktop\tdata\key_datas') (New-RandBytes 1024 '') 'token'
            New-Bait (Join-Path $uh 'AppData\Roaming\Telegram Desktop\tdata\D877F783D5D3EF8C\map1') (New-RandBytes 2048 '') 'token'
            New-Bait 'C:\Program Files (x86)\Steam\config\loginusers.vdf' (New-Text ('"users"' + "`r`n" + '{' + "`r`n" + '  "76561198000000001" { "AccountName" "ssbaituser" "RememberPassword" "1" }' + "`r`n" + '}')) 'token'
            # kripto cuzdanlar
            New-Bait (Join-Path $uh 'AppData\Roaming\Exodus\exodus.wallet\seed.seco') (New-RandBytes 2048 '') 'wallet'
            New-Bait (Join-Path $uh 'AppData\Roaming\Electrum\wallets\default_wallet') (New-Text ('{"keystore":{"type":"bip32","xprv":"' + (New-Part 90) + '"},"wallet_type":"standard"}')) 'wallet'
            New-Bait (Join-Path $uh 'AppData\Roaming\Bitcoin\wallets\wallet.dat') (New-RandBytes 65536 '') 'wallet'
            New-Bait (Join-Path $uh 'AppData\Roaming\atomic\Local Storage\leveldb\000003.log') (New-Text ('{"vault":"' + (New-Part 80) + '"}')) 'wallet'
            New-Bait (Join-Path $uh 'AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\000003.log') (New-Text ('{"vault":{"data":"' + (New-Part 100) + '","iv":"' + (New-Part 22) + '","salt":"' + (New-Part 44) + '"}}')) 'wallet'
            New-Bait (Join-Path $uh 'Documents\wallet seed phrase.txt') (New-Text 'abandon ability able about above absent absorb abstract absurd abuse access accident') 'wallet'
            # sunucu / bulut kimlikleri
            New-Bait (Join-Path $uh '.ssh\id_rsa') (New-Text ('-----BEGIN OPENSSH PRIVATE KEY-----' + "`n" + (New-Part 64) + "`n" + (New-Part 64) + "`n" + '-----END OPENSSH PRIVATE KEY-----' + "`n")) 'cred'
            New-Bait (Join-Path $uh '.aws\credentials') (New-Text ('[default]' + "`n" + 'aws_access_key_id = AKIA' + (New-Part 16).ToUpper().Replace('-', 'A').Replace('_', 'B') + "`n" + 'aws_secret_access_key = ' + (New-Part 40) + "`n")) 'cred'
            New-Bait (Join-Path $uh 'AppData\Roaming\FileZilla\recentservers.xml') (New-Text ('<FileZilla3><RecentServers><Server><Host>ftp.example.com</Host><User>ssbait</User><Pass encoding="base64">' + [Convert]::ToBase64String((New-RandBytes 12 '')) + '</Pass></Server></RecentServers></FileZilla3>')) 'cred'
            New-Bait (Join-Path $uh 'Documents\passwords.txt') (New-Text ('gmail: ssbait@example.com / ' + (New-Part 12) + "`r`n" + 'bank: ' + (New-Part 10))) 'cred'
        } catch { Add-Err 'bait-setup' $_ }
        # dosya sistemi denetimi: sahte dosyalar okunursa Security gunlugune 4663 dusur
        try { & auditpol.exe /set /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}" /success:enable | Out-Null } catch { Add-Err 'bait-auditpol' $_ }
        $okN = 0
        foreach ($bf in $baitFiles) {
            try {
                $acl = Get-Acl -LiteralPath $bf.path -Audit
                $rule = New-Object System.Security.AccessControl.FileSystemAuditRule('Everyone', 'ReadData', 'None', 'None', 'Success')
                $acl.AddAuditRule($rule)
                Set-Acl -LiteralPath $bf.path -AclObject $acl
                $okN++
            } catch { if ($okN -eq 0) { Add-Err 'bait-sacl' $_ } }
        }
        $baitAuditOk = ($okN -gt 0)
        # pano tuzagi: ornek calisirken sahte kripto adresleri panoya konur; degistirilirse "clipper" olabilir
        [void]$clipPlan.Add(@{ at = 4; type = 'btc'; value = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh' })
        [void]$clipPlan.Add(@{ at = 24; type = 'eth'; value = '0x742d35Cc6634C0532925a3b844Bc454e4438f44e' })
        # sahte kullanici etkinligi: fare hareketi (bazi zararlilar etkilesim bekler)
        try {
            Add-Type -TypeDefinition 'using System.Runtime.InteropServices; public class SSInput { [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y); }'
            $mouseOk = $true
        } catch { Add-Err 'mouse' $_ }
    }

    # --- Taban durum ---
    function Get-RegSnap {
        $snap = @{}
        $keys = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run',
            'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon', 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon',
            'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Windows',
            'HKCU:\Environment', 'HKLM:\System\CurrentControlSet\Control\Session Manager',
            'HKLM:\Software\Microsoft\Windows Defender\Exclusions\Paths', 'HKLM:\Software\Microsoft\Windows Defender\Exclusions\Extensions', 'HKLM:\Software\Microsoft\Windows Defender\Exclusions\Processes',
            'HKLM:\Software\Policies\Microsoft\Windows Defender', 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-Time Protection',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System',
            'HKCU:\Software\Classes\ms-settings\Shell\Open\command', 'HKCU:\Software\Classes\mscfile\shell\open\command', 'HKCU:\Software\Classes\exefile\shell\open\command'
        )
        foreach ($k in $keys) {
            try {
                if (Test-Path -LiteralPath $k) {
                    $p = Get-ItemProperty -LiteralPath $k -ErrorAction Stop
                    foreach ($prop in $p.PSObject.Properties) {
                        if ($prop.Name -like 'PS*') { continue }
                        $snap[($k + '::' + $prop.Name)] = [string]$prop.Value
                    }
                    $snap[($k + '::<anahtar var>')] = '1'
                }
            } catch { }
        }
        try {
            $ifeo = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
            foreach ($sub in (Get-ChildItem -LiteralPath $ifeo -ErrorAction Stop)) {
                $dbg = $null
                try { $dbg = (Get-ItemProperty -LiteralPath $sub.PSPath -Name Debugger -ErrorAction Stop).Debugger } catch { }
                if ($dbg) { $snap[($ifeo + '\' + $sub.PSChildName + '::Debugger')] = [string]$dbg }
            }
        } catch { }
        return $snap
    }
    function Get-TaskSnap {
        $s = @{}
        try { foreach ($t in (Get-ScheduledTask -ErrorAction Stop)) { $s[($t.TaskPath + $t.TaskName)] = '1' } } catch { }
        return $s
    }
    function Get-SvcSnap {
        $s = @{}
        try { foreach ($v in (Get-CimInstance Win32_Service -ErrorAction Stop)) { $s[[string]$v.Name] = ([string]$v.PathName + '|' + [string]$v.StartMode) } } catch { }
        return $s
    }
    $regBefore = Get-RegSnap
    $taskBefore = Get-TaskSnap
    $svcBefore = Get-SvcSnap
    $hkBefore = $null
    $hkcuOn = ($Cfg.hkcuDiff -eq $true)
    if ($hkcuOn) {
        try {
            & reg.exe export HKCU (Join-Path $RunDir 'hkcu_before.reg') /y | Out-Null
            $hkBefore = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($ln in [System.IO.File]::ReadAllLines((Join-Path $RunDir 'hkcu_before.reg'))) { [void]$hkBefore.Add($ln) }
        } catch { Add-Err 'hkcu-before' $_; $hkBefore = $null }
    }
    $baseKeys = @{}
    $procBefore = @()
    try { $procBefore = @(Get-CimInstance Win32_Process -ErrorAction Stop) } catch { Add-Err 'proc-before' $_ }
    foreach ($pp in $procBefore) { $baseKeys[([string]$pp.ProcessId + '|' + [string]$pp.CreationDate.Ticks)] = $true }

    # --- Dosya sistemi izleyicileri ---
    $global:ssFsEv = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
    $global:ssFsSeen = [hashtable]::Synchronized(@{})
    $global:ssSkipA = (Join-Path $Base 'in')
    $global:ssSkipB = (Join-Path $Base 'out')
    $script:Watchers = New-Object System.Collections.ArrayList
    $roots = @(
        @{ p = 'C:\Users\WDAGUtilityAccount'; r = $true }, @{ p = 'C:\ProgramData'; r = $true }, @{ p = 'C:\Users\Public'; r = $true },
        @{ p = 'C:\Windows\Temp'; r = $true }, @{ p = 'C:\ssrun'; r = $true },
        @{ p = 'C:\Windows'; r = $false }, @{ p = 'C:\Windows\System32'; r = $false }, @{ p = 'C:\Windows\SysWOW64'; r = $false }
    )
    foreach ($ex in @($Cfg.watchExtra)) { if ($ex) { $roots += @{ p = [string]$ex; r = $true } } }
    $wi = 0
    foreach ($rt in $roots) {
        try {
            if (-not (Test-Path -LiteralPath $rt.p)) { continue }
            $w = New-Object System.IO.FileSystemWatcher
            $w.Path = $rt.p
            $w.IncludeSubdirectories = [bool]$rt.r
            $w.InternalBufferSize = 65536
            $w.NotifyFilter = [System.IO.NotifyFilters]'FileName, DirectoryName, LastWrite, Size'
            foreach ($evn in @('Created', 'Changed', 'Deleted', 'Renamed')) {
                $wi++
                Register-ObjectEvent -InputObject $w -EventName $evn -SourceIdentifier ('ss_fs_' + $wi) -Action {
                    try {
                        $a = $Event.SourceEventArgs
                        $fp = [string]$a.FullPath
                        if ($fp.StartsWith($global:ssSkipA) -or $fp.StartsWith($global:ssSkipB)) { return }
                        $k = $a.ChangeType.ToString()
                        $key = $k + '|' + $fp
                        if ($global:ssFsSeen.ContainsKey($key)) { return }
                        if ($global:ssFsEv.Count -ge 6000) { return }
                        $global:ssFsSeen[$key] = 1
                        $old = ''
                        if ($k -eq 'Renamed') { $old = [string]$a.OldFullPath }
                        [void]$global:ssFsEv.Add(@{ k = $k; p = $fp; o = $old; t = (Get-Date).ToUniversalTime().ToString('o') })
                    } catch { }
                } | Out-Null
            }
            $w.EnableRaisingEvents = $true
            [void]$script:Watchers.Add($w)
        } catch { Add-Err ('watch ' + $rt.p) $_ }
    }

    # --- Ornegi baslat ---
    $launch = $Cfg.launch
    $rootProc = $null
    $launchErr = $null
    $launchedProg = ''
    $launchedArgs = ''
    $LaunchAt = Get-Date
    if (-not $existsBefore) {
        $launchErr = 'Ornek dosyasi kopyalandiktan sonra kayboldu (buyuk olasilikla Defender karantinaya aldi).'
    } elseif ($launch.skip -eq $true) {
        $launchErr = [string]$launch.skipReason
    } else {
        foreach ($s in @($Cfg.preSteps)) { if ($s) { try { Invoke-Expression ([string]$s) } catch { Add-Err 'preStep' $_ } } }
        try {
            $prog = ([string]$launch.program).Replace('{sample}', $SamplePath).Replace('{dir}', $RunDir).Replace('{name}', $SampleName).Replace('{java}', $JavaExe)
            $argList = @()
            foreach ($a in @($launch.args)) {
                $x = ([string]$a).Replace('{sample}', $SamplePath).Replace('{dir}', $RunDir).Replace('{name}', $SampleName).Replace('{java}', $JavaExe)
                if ($x -match '\s') { $x = '"' + $x + '"' }
                $argList += $x
            }
            $launchedProg = $prog
            $launchedArgs = ($argList -join ' ')
            $sp = @{ FilePath = $prog; WorkingDirectory = $RunDir; PassThru = $true; ErrorAction = 'Stop' }
            if ($argList.Count -gt 0) { $sp['ArgumentList'] = $launchedArgs }
            Set-Status 'launch' 0 $Plan
            $LaunchAt = Get-Date
            $rootProc = Start-Process @sp
        } catch { $launchErr = 'Baslatilamadi: ' + $_.Exception.Message; Add-Err 'launch' $_ }
    }

    # --- Izleme dongusu ---
    $pollProcs = New-Object System.Collections.ArrayList
    $seenProc = @{}
    $conns = @{}
    $connList = New-Object System.Collections.ArrayList
    $cycle = 0
    $quietSince = $null
    $lastActivity = -1
    $rootExited = $false
    $exitCode = $null
    $stoppedEarly = $false
    $endAt = $LaunchAt.AddSeconds($Plan)
    $idleSec = [int]$Cfg.idleSec
    if ($idleSec -lt 3) { $idleSec = 3 }
    $keepWatching = ($rootProc -ne $null)
    if (-not $keepWatching) { $endAt = (Get-Date).AddSeconds(2) }

    while ((Get-Date) -lt $endAt) {
        Start-Sleep -Milliseconds 500
        $cycle++
        $now = Get-Date
        if ($baitOn) {
            if ($mouseOk -and (($cycle % 3) -eq 0)) { try { [void][SSInput]::SetCursorPos(150 + $rng.Next(0, 700), 150 + $rng.Next(0, 350)) } catch { } }
            $clipPending = $false
            foreach ($cp in $clipPlan) {
                if (-not $cp.done) {
                    $clipPending = $true
                    if ($cycle -ge $cp.at) { try { Set-Clipboard -Value $cp.value; $cp.setAt = $cycle } catch { $cp.err = $true }; $cp.done = $true }
                } elseif (-not $cp.checked) {
                    if ($cp.err) { $cp.checked = $true }
                    elseif ($cycle -ge ($cp.setAt + 6)) {
                        $cp.checked = $true
                        try { $seen = [string](Get-Clipboard -Raw -ErrorAction Stop); if ($seen.Length -gt 200) { $seen = $seen.Substring(0, 200) }; [void]$clipLog.Add(@{ type = $cp.type; set = $cp.value; seen = $seen; changed = ($seen.Trim() -ne $cp.value) }) } catch { }
                    } else { $clipPending = $true }
                }
            }
        }
        $list = @()
        try { $list = @(Get-CimInstance Win32_Process -ErrorAction Stop) } catch { }
        $children = @{}
        foreach ($pp in $list) {
            $kk = [string]$pp.ProcessId + '|' + [string]$pp.CreationDate.Ticks
            if ($baseKeys.ContainsKey($kk) -or $seenProc.ContainsKey($kk)) { continue }
            $seenProc[$kk] = $true
            if ($pollProcs.Count -lt 1500) {
                [void]$pollProcs.Add(@{ pid = [int]$pp.ProcessId; ppid = [int]$pp.ParentProcessId; name = [string]$pp.Name; cmd = [string]$pp.CommandLine; path = [string]$pp.ExecutablePath; start = (Iso $pp.CreationDate) })
            }
        }
        $alive = $false
        if ($rootProc) {
            try { $rootProc.Refresh(); if ($rootProc.HasExited) { if (-not $rootExited) { $rootExited = $true; try { $exitCode = $rootProc.ExitCode } catch { } } } } catch { }
            $tree = @{}
            if (-not $rootExited) { $tree[[int]$rootProc.Id] = $true }
            for ($i = 0; $i -lt 4; $i++) { foreach ($pp in $list) { if ($tree.ContainsKey([int]$pp.ParentProcessId) -and -not $tree.ContainsKey([int]$pp.ProcessId)) { $tree[[int]$pp.ProcessId] = $true } } }
            $alive = ($tree.Count -gt 0)
        }
        if (($cycle % 4) -eq 0) {
            try {
                foreach ($c in @(Get-NetTCPConnection -ErrorAction Stop)) {
                    if ($c.State -eq 'Listen' -or $c.State -eq 'Bound') { continue }
                    $ra = [string]$c.RemoteAddress
                    if ($ra -eq '127.0.0.1' -or $ra -eq '::1' -or $ra -eq '0.0.0.0' -or $ra -eq '::') { continue }
                    $ck = $ra + ':' + [string]$c.RemotePort + ':' + [string]$c.OwningProcess
                    if (-not $conns.ContainsKey($ck) -and $connList.Count -lt 400) {
                        $conns[$ck] = 1
                        [void]$connList.Add(@{ remote = $ra; port = [int]$c.RemotePort; state = [string]$c.State; pid = [int]$c.OwningProcess; t = (Iso (Get-Date)) })
                    }
                }
            } catch { }
        }
        if (($cycle % 4) -eq 0) { Set-Status 'running' ([int]($now - $LaunchAt).TotalSeconds) $Plan }
        if ($Cfg.stopWhenIdle -eq $true -and $rootProc -and -not $alive) {
            $act = $seenProc.Count + $global:ssFsEv.Count + $connList.Count
            if ($act -ne $lastActivity) { $lastActivity = $act; $quietSince = $now }
            elseif ($quietSince -and (($now - $quietSince).TotalSeconds -ge $idleSec) -and -not $clipPending) { $stoppedEarly = $true; break }
        }
    }
    $elapsed = [int]((Get-Date) - $LaunchAt).TotalSeconds
    $cpuSec = $null
    $aliveEnd = $false
    if ($rootProc) {
        try { $rootProc.Refresh(); $aliveEnd = (-not $rootProc.HasExited); if ($aliveEnd) { $cpuSec = [math]::Round($rootProc.TotalProcessorTime.TotalSeconds, 2) } else { if (-not $rootExited) { $rootExited = $true; try { $exitCode = $rootProc.ExitCode } catch { } } } } catch { }
    }

    Set-Status 'collect' $elapsed $Plan
    foreach ($s in @($Cfg.postSteps)) { if ($s) { try { Invoke-Expression ([string]$s) } catch { Add-Err 'postStep' $_ } } }

    # --- Ekran goruntusu ---
    $shot = $null
    if ($Cfg.screenshot -eq $true) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            Add-Type -AssemblyName System.Drawing
            $vs = [System.Windows.Forms.SystemInformation]::VirtualScreen
            if ($vs.Width -gt 0 -and $vs.Height -gt 0) {
                $bmp = New-Object System.Drawing.Bitmap($vs.Width, $vs.Height)
                $g = [System.Drawing.Graphics]::FromImage($bmp)
                $g.CopyFromScreen($vs.Location, [System.Drawing.Point]::Empty, $vs.Size)
                $g.Dispose()
                $nw = $vs.Width; $nh = $vs.Height
                if ($nw -gt 1280) { $nh = [int]($nh * 1280 / $nw); $nw = 1280 }
                $thumb = New-Object System.Drawing.Bitmap($bmp, $nw, $nh)
                $thumb.Save((Join-Path $OutDir 'screen.png'), [System.Drawing.Imaging.ImageFormat]::Png)
                $thumb.Dispose(); $bmp.Dispose()
                $shot = @{ file = 'screen.png'; w = $nw; h = $nh }
            }
        } catch { Add-Err 'screenshot' $_ }
    }

    # --- Acik pencereler ---
    $wins = @()
    try { foreach ($pr in @(Get-Process -ErrorAction Stop)) { if ($pr.MainWindowTitle -and $wins.Count -lt 40) { $wins += @{ pid = [int]$pr.Id; name = [string]$pr.ProcessName; title = [string]$pr.MainWindowTitle } } } } catch { }

    # --- Izleyicileri kapat ---
    foreach ($w in $script:Watchers) { try { $w.EnableRaisingEvents = $false } catch { } }
    try { Get-EventSubscriber | Where-Object { $_.SourceIdentifier -like 'ss_fs_*' } | Unregister-Event -Force } catch { }
    Start-Sleep -Milliseconds 400

    # --- Surec denetim kayitlari (4688) ---
    $audit = New-Object System.Collections.ArrayList
    try {
        $evs = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = $ScriptStart } -ErrorAction Stop)
        foreach ($e in $evs) {
            if ($audit.Count -ge 1500) { break }
            $d = @{}
            try { foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' } } catch { }
            $npid = 0; $cpid = 0
            try { $npid = [Convert]::ToInt32(([string]$d['NewProcessId']).Replace('0x', ''), 16) } catch { }
            try { $cpid = [Convert]::ToInt32(([string]$d['ProcessId']).Replace('0x', ''), 16) } catch { }
            [void]$audit.Add(@{ pid = $npid; ppid = $cpid; path = [string]$d['NewProcessName']; cmd = [string]$d['CommandLine']; parentPath = [string]$d['ParentProcessName']; start = (Iso $e.TimeCreated) })
        }
    } catch { Add-Err 'audit-read' $_ }

    # --- Tuzak dosya okumalari (4663) ---
    $baitReads = New-Object System.Collections.ArrayList
    if ($baitOn -and $baitAuditOk) {
        try {
            $paths = @{}
            foreach ($bf in $baitFiles) { $paths[([string]$bf.path).ToLowerInvariant()] = [string]$bf.kind }
            $evs2 = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4663; StartTime = $LaunchAt.AddSeconds(-1) } -ErrorAction Stop)
            $seenR = @{}
            foreach ($e in $evs2) {
                if ($baitReads.Count -ge 150) { break }
                $d = @{}
                try { foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $d[[string]$n.Name] = [string]$n.'#text' } } catch { }
                $obj = ([string]$d['ObjectName']).ToLowerInvariant()
                if (-not $paths.ContainsKey($obj)) { continue }
                $rpid = 0
                try { $rpid = [Convert]::ToInt32(([string]$d['ProcessId']).Replace('0x', ''), 16) } catch { }
                $rk = [string]$rpid + '|' + $obj
                if ($seenR.ContainsKey($rk)) { continue }
                $seenR[$rk] = $true
                [void]$baitReads.Add(@{ pid = $rpid; proc = [string]$d['ProcessName']; path = [string]$d['ObjectName']; kind = $paths[$obj]; t = (Iso $e.TimeCreated) })
            }
        } catch { if ($_.Exception.Message -notmatch 'No events|Hicbir|bulunamad') { Add-Err 'bait-read' $_ } }
    }

    # --- Kayit defteri / gorev / hizmet farklari ---
    $regAfter = Get-RegSnap
    $regChanges = New-Object System.Collections.ArrayList
    foreach ($k in $regAfter.Keys) {
        if (-not $regBefore.ContainsKey($k)) { [void]$regChanges.Add(@{ c = 'added'; k = [string]$k; v = [string]$regAfter[$k] }) }
        elseif ($regBefore[$k] -ne $regAfter[$k]) { [void]$regChanges.Add(@{ c = 'changed'; k = [string]$k; v = [string]$regAfter[$k]; old = [string]$regBefore[$k] }) }
    }
    foreach ($k in $regBefore.Keys) { if (-not $regAfter.ContainsKey($k)) { [void]$regChanges.Add(@{ c = 'removed'; k = [string]$k; v = ''; old = [string]$regBefore[$k] }) } }
    $hkChanges = New-Object System.Collections.ArrayList
    if ($hkcuOn -and $hkBefore) {
        try {
            & reg.exe export HKCU (Join-Path $RunDir 'hkcu_after.reg') /y | Out-Null
            $cur = ''
            foreach ($ln in [System.IO.File]::ReadAllLines((Join-Path $RunDir 'hkcu_after.reg'))) {
                if ($ln.StartsWith('[')) { $cur = $ln; continue }
                if ($ln.Length -eq 0) { continue }
                if (-not $hkBefore.Contains($ln)) { if ($hkChanges.Count -lt 800) { [void]$hkChanges.Add(@{ key = $cur; line = $ln }) } }
            }
        } catch { Add-Err 'hkcu-after' $_ }
    }
    $taskAfter = Get-TaskSnap
    $newTasks = New-Object System.Collections.ArrayList
    foreach ($k in $taskAfter.Keys) {
        if (-not $taskBefore.ContainsKey($k)) {
            $act = ''
            try {
                $tn = Split-Path -Leaf ([string]$k).TrimEnd('\')
                $tp = ([string]$k).Substring(0, ([string]$k).Length - $tn.Length)
                $tt = Get-ScheduledTask -TaskName $tn -TaskPath $tp -ErrorAction Stop
                $act = (@($tt.Actions | ForEach-Object { ([string]$_.Execute + ' ' + [string]$_.Arguments).Trim() }) -join ' ; ')
            } catch { }
            [void]$newTasks.Add(@{ name = [string]$k; action = $act })
        }
    }
    $svcAfter = Get-SvcSnap
    $svcChanges = New-Object System.Collections.ArrayList
    foreach ($k in $svcAfter.Keys) {
        if (-not $svcBefore.ContainsKey($k)) { [void]$svcChanges.Add(@{ c = 'added'; name = [string]$k; v = [string]$svcAfter[$k] }) }
        elseif ($svcBefore[$k] -ne $svcAfter[$k]) { [void]$svcChanges.Add(@{ c = 'changed'; name = [string]$k; v = [string]$svcAfter[$k]; old = [string]$svcBefore[$k] }) }
    }
    $wmi = New-Object System.Collections.ArrayList
    foreach ($cls in @('CommandLineEventConsumer', 'ActiveScriptEventConsumer', '__EventFilter')) {
        try { foreach ($o in @(Get-CimInstance -Namespace 'root\subscription' -ClassName $cls -ErrorAction Stop)) { if ($wmi.Count -lt 40) { [void]$wmi.Add(@{ cls = $cls; name = [string]$o.Name; detail = [string]($o.CommandLineTemplate + $o.ScriptText + $o.Query) }) } } } catch { }
    }

    # --- DNS ---
    $dns = New-Object System.Collections.ArrayList
    $dnsSeen = @{}
    try {
        $dev = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-DNS-Client/Operational'; Id = @(3006, 3008, 3020) } -ErrorAction Stop)
        foreach ($e in $dev) {
            $qn = ''
            try { foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { if ([string]$n.Name -eq 'QueryName') { $qn = [string]$n.'#text' } } } catch { }
            if ($qn -and -not $dnsSeen.ContainsKey($qn) -and $dns.Count -lt 400) { $dnsSeen[$qn] = 1; [void]$dns.Add(@{ name = $qn; t = (Iso $e.TimeCreated) }) }
        }
    } catch { }
    try {
        foreach ($c in @(Get-DnsClientCache -ErrorAction Stop)) {
            $qn = [string]$c.Entry
            if ($qn -and -not $dnsSeen.ContainsKey($qn) -and $dns.Count -lt 400) { $dnsSeen[$qn] = 1; [void]$dns.Add(@{ name = $qn; t = $null }) }
        }
    } catch { }

    # --- Defender tespitleri ---
    $mpDet = New-Object System.Collections.ArrayList
    $mpThr = New-Object System.Collections.ArrayList
    try { foreach ($d in @(Get-MpThreatDetection -ErrorAction Stop)) { if ($mpDet.Count -lt 40) { [void]$mpDet.Add(@{ id = [string]$d.ThreatID; proc = [string]$d.ProcessName; res = (@($d.Resources) -join '; '); t = (Iso $d.InitialDetectionTime) }) } } } catch { }
    try { foreach ($d in @(Get-MpThreat -ErrorAction Stop)) { if ($mpThr.Count -lt 40) { [void]$mpThr.Add(@{ id = [string]$d.ThreatID; name = [string]$d.ThreatName; sev = [string]$d.SeverityID }) } } } catch { }

    # --- Dosya olaylari ve dusen dosyalar ---
    $events = @($global:ssFsEv.ToArray())
    $existsAfter = Test-Path -LiteralPath $SamplePath
    $items = New-Object System.Collections.ArrayList
    $copied = 0; $copiedBytes = 0
    $maxN = [int]$Cfg.maxDropped
    $maxB = [int64]$Cfg.maxDroppedMB * 1MB
    $cand = @{}
    foreach ($e in $events) { if ($e.k -ne 'Deleted') { $cand[[string]$e.p] = 1 } }
    $dropDir = Join-Path $OutDir 'dropped'
    $execExt = '\.(exe|dll|scr|com|pif|sys|ocx|cpl|msi|jar|bat|cmd|ps1|vbs|vbe|js|jse|wsf|hta|lnk|py)$'
    $n = 0
    foreach ($p in $cand.Keys) {
        if ($n -ge 500) { break }
        try {
            if ($p -eq $SamplePath) { continue }
            $fi = Get-Item -LiteralPath $p -Force -ErrorAction Stop
            if ($fi.PSIsContainer) { continue }
            $n++
            $head = Get-Head $p 4
            $mz = ($head.Length -ge 2 -and $head[0] -eq 0x4D -and $head[1] -eq 0x5A)
            $zip = ($head.Length -ge 4 -and $head[0] -eq 0x50 -and $head[1] -eq 0x4B -and $head[2] -eq 3 -and $head[3] -eq 4)
            $extOk = ($p -match $execExt)
            if (-not ($mz -or $zip -or $extOk)) { continue }
            $sha = Get-Sha256Stream $p
            $row = @{ path = [string]$p; size = [int64]$fi.Length; sha256 = $sha; mz = $mz; zip = $zip; sameAsSample = ($sha -and $sha -eq $sha0); copied = $false }
            if ($sha -and -not $row.sameAsSample -and $copied -lt $maxN -and $fi.Length -le ($maxB) -and ($copiedBytes + $fi.Length) -le ($maxB * 4)) {
                try {
                    New-Item -ItemType Directory -Force -Path $dropDir | Out-Null
                    $dst = Join-Path $dropDir ($sha + '.bin')
                    if (-not (Test-Path -LiteralPath $dst)) {
                        $in = New-Object System.IO.FileStream($p, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                        $outS = New-Object System.IO.FileStream($dst, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
                        $in.CopyTo($outS); $outS.Dispose(); $in.Dispose()
                        $copied++; $copiedBytes += $fi.Length
                    }
                    $row.copied = $true
                } catch { }
            }
            if ($items.Count -lt 200) { [void]$items.Add($row) }
        } catch { }
    }

    $os = $null
    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { }
    $sampleInfo = [ordered]@{
        name = $SampleName; sha256 = $sha0; existedAfterCopy = [bool]$existsBefore; existsAfter = [bool]$existsAfter
        launchError = $launchErr; program = $launchedProg; args = $launchedArgs
        rootPid = $(if ($rootProc) { [int]$rootProc.Id } else { 0 })
        exited = [bool]$rootExited; exitCode = $exitCode; aliveAtEnd = [bool]$aliveEnd; cpuSec = $cpuSec
    }
    $result['endedAt'] = (Iso (Get-Date))
    $result['elapsedSec'] = $elapsed
    $result['stoppedEarly'] = [bool]$stoppedEarly
    $result['guest'] = @{ os = $(if ($os) { [string]$os.Caption } else { '' }); build = $(if ($os) { [string]$os.BuildNumber } else { '' }); networking = [string]$Cfg.networking; defender = [string]$Cfg.defender; firewallLanBlock = [bool]$fwBlock; ps = $PSVersionTable.PSVersion.ToString() }
    $result['sample'] = $sampleInfo
    $result['processes'] = @{ audit = @($audit.ToArray()); poll = @($pollProcs.ToArray()) }
    $result['files'] = @{ events = @($events); items = @($items.ToArray()); eventCap = ($events.Count -ge 6000) }
    $result['registry'] = @{ persistence = @($regChanges.ToArray()); hkcu = @($hkChanges.ToArray()) }
    $result['tasks'] = @($newTasks.ToArray())
    $result['services'] = @($svcChanges.ToArray())
    $result['wmi'] = @($wmi.ToArray())
    $result['network'] = @{ dns = @($dns.ToArray()); connections = @($connList.ToArray()) }
    $result['defenderResult'] = @{ detections = @($mpDet.ToArray()); threats = @($mpThr.ToArray()) }
    $result['windows'] = @($wins)
    $result['screenshot'] = $shot
    $result['bait'] = @{ enabled = [bool]$baitOn; auditOk = [bool]$baitAuditOk; mouse = [bool]$mouseOk; files = @($baitFiles | ForEach-Object { @{ path = [string]$_.path; kind = [string]$_.kind } }); reads = @($baitReads.ToArray()); clipboard = @($clipLog.ToArray()) }
    $result['errors'] = @($script:Errors.ToArray())
    $result['notes'] = @($script:Notes.ToArray())
} catch {
    $result['fatal'] = [string]$_.Exception.Message
    $result['errors'] = @($script:Errors.ToArray())
}

try {
    $json = ConvertTo-Json -InputObject $result -Depth 8 -Compress
    Write-OutText 'result.json' $json
} catch {
    try { Write-OutText 'result.json' (ConvertTo-Json -InputObject @{ schema = 1; fatal = ('JSON yazilamadi: ' + $_.Exception.Message) } -Compress) } catch { }
}
Set-Status 'done' 0 $Plan
try { Write-OutText 'done.flag' 'ok' } catch { }
Start-Sleep -Seconds 1
& shutdown.exe /s /t 2 /f
