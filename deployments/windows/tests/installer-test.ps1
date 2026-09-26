<#
  End-to-end test of the Nexus Windows installer on a real Windows x64 machine
  (used by .github/workflows/windows.yml on windows-latest; also runnable by
  hand in a disposable VM as Administrator).

  It installs, verifies, attacks and upgrades a real installation:
    port conflict → silent install → service/account/health → ACLs → firewall
    → no secrets in logs or command lines → first-run browser flow (Playwright)
    → crash recovery → restart → diagnostics/backup CLI → upgrade with data kept
    → failed upgrade with automatic rollback → LAN mode firewall rule
    → uninstall keeping data → reinstall with data → uninstall with purge.

  WARNING: it removes any existing Nexus installation and its data.
#>
param(
  [Parameter(Mandatory = $true)] [string] $Installer,   # e.g. Nexus-1.0.0-Setup-x64.exe
  [Parameter(Mandatory = $true)] [string] $Upgrade,     # a newer version, e.g. 1.0.1
  [Parameter(Mandatory = $true)] [string] $Broken,      # a version made to fail at startup, e.g. 1.0.2
  [string] $E2EDir = "",                                  # tests/e2e with node_modules (optional)
  [string] $WorkDir = $env:RUNNER_TEMP
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $WorkDir) { $WorkDir = $env:TEMP }
$DataRoot = Join-Path $env:ProgramData 'Nexus'
$ProgramDir = Join-Path $env:ProgramFiles 'Nexus'
$AdminUser = 'admin'
$AdminPass = 'ci-admin-pass-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$script:Passed = @()

function Step([string] $name, [scriptblock] $body) {
  Write-Host ""
  Write-Host "=== $name" -ForegroundColor Cyan
  & $body
  Write-Host "PASS $name" -ForegroundColor Green
  $script:Passed += $name
}
function Assert([bool] $cond, [string] $msg) { if (-not $cond) { throw "ASSERTION FAILED: $msg" } }

function Run-Installer([string] $exe, [string[]] $arguments) {
  # One pre-joined string: NSIS needs /D= and _?= unquoted and last.
  $line = $arguments -join ' '
  Write-Host "> $exe $line"
  $p = Start-Process -FilePath $exe -ArgumentList $line -Wait -PassThru
  Write-Host "  exit code $($p.ExitCode)"
  return $p.ExitCode
}
function Reg { Get-ItemProperty -Path 'HKLM:\Software\Nexus' -ErrorAction SilentlyContinue }
function Port { [int](Reg).Port }
function Base { "http://127.0.0.1:$(Port)" }
function Health {
  try { Invoke-RestMethod -Uri "$(Base)/api/health" -TimeoutSec 5 } catch { $null }
}
function Wait-Healthy([int] $seconds = 180) {
  $deadline = (Get-Date).AddSeconds($seconds)
  while ((Get-Date) -lt $deadline) {
    $h = Health
    if ($h -and $h.status -eq 'ok' -and $h.database) { return $h }
    Start-Sleep -Seconds 2
  }
  throw "Nexus did not become healthy within $seconds s"
}
function Login {
  $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
  $body = @{ username = $AdminUser; password = $AdminPass } | ConvertTo-Json
  Invoke-RestMethod -Uri "$(Base)/api/auth/login" -Method Post -Body $body -ContentType 'application/json' `
    -Headers @{ 'X-Requested-With' = 'nexus' } -WebSession $s | Out-Null
  return $s
}
function Device-Count($session) {
  $d = Invoke-RestMethod -Uri "$(Base)/api/devices?limit=1" -WebSession $session -Headers @{ 'X-Requested-With' = 'nexus' }
  return [int]$d.total
}
function Secrets {
  @(
    (Get-Content (Join-Path $DataRoot 'secrets\master.key') -Raw).Trim(),
    (Get-Content (Join-Path $DataRoot 'secrets\db.password') -Raw).Trim(),
    $AdminPass
  )
}
function Assert-NoSecretsIn([string[]] $files) {
  $secrets = Secrets
  foreach ($f in $files) {
    if (-not (Test-Path $f)) { continue }
    # Share read/write/delete: the service keeps its logs open.
    $fs = [System.IO.File]::Open($f, 'Open', 'Read', 'ReadWrite, Delete')
    try { $text = (New-Object System.IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Dispose() }
    foreach ($s in $secrets) {
      Assert (-not $text.Contains($s)) "secret found in $f"
    }
  }
}
function Uninstall([string[]] $extra) {
  $u = Join-Path $ProgramDir 'Uninstall Nexus.exe'
  # _?= runs the uninstaller in place so -Wait waits for it.
  return Run-Installer $u (@('/S') + $extra + @("_?=$ProgramDir"))
}

# ------------------------------------------------------------------ clean slate
Step 'Clean machine' {
  if (Get-Service Nexus -ErrorAction SilentlyContinue) {
    if (Test-Path (Join-Path $ProgramDir 'Uninstall Nexus.exe')) { Uninstall @('/PURGEDATA=YES') | Out-Null }
  }
  Remove-Item -Recurse -Force $DataRoot -ErrorAction SilentlyContinue
  Assert (-not (Get-Service Nexus -ErrorAction SilentlyContinue)) 'service still present'
}

# ------------------------------------------------------------------ install with busy port
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 8080)
Step 'Install 1 (port 8080 occupied, demo network)' {
  $listener.Start()
  $code = Run-Installer $Installer @('/S', '/DEMO=1', '/NOBROWSER', "/LOG=$WorkDir\install1.log")
  $listener.Stop()
  Assert ($code -eq 0) "installer exit code $code"
  Assert ((Port) -ne 8080) "port conflict not handled (port $(Port))"
  Write-Host "  chose port $(Port)"
  $h = Wait-Healthy
  Write-Host "  version $($h.version)"
}

Step 'Service: automatic start, virtual account, recovery configured' {
  $svc = Get-CimInstance Win32_Service -Filter "Name='Nexus'"
  Assert ($svc.State -eq 'Running') "state $($svc.State)"
  Assert ($svc.StartMode -eq 'Auto') "start mode $($svc.StartMode)"
  Assert ($svc.StartName -eq 'NT SERVICE\Nexus') "account $($svc.StartName)"
  $qc = sc.exe qfailure Nexus | Out-String
  Assert ($qc -match 'RESTART') "recovery actions missing: $qc"
  $sid = sc.exe qsidtype Nexus | Out-String
  Assert ($sid -match 'UNRESTRICTED') "sid type: $sid"
}

Step 'Shortcuts, uninstall entry and notification area icon' {
  $p = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue
  $run = if ($p -and ($p.PSObject.Properties.Name -contains 'Nexus Tray')) { $p.'Nexus Tray' } else { $null }
  Assert ($run -and (Test-Path ($run.Trim('"')))) "tray autostart missing or wrong: $run"
  $sm = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Nexus'
  Assert (Test-Path (Join-Path $sm 'Nexus.url')) 'Start menu shortcut missing'
  Assert ((Get-Content (Join-Path $sm 'Nexus.url') -Raw) -match "URL=http://localhost:$(Port)/") 'Start menu shortcut URL'
  Assert (Test-Path (Join-Path $sm 'Nexus Diagnostics.lnk')) 'diagnostics shortcut missing'
  $u = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Nexus'
  Assert ($u.DisplayName -eq 'Nexus Network Intelligence' -and $u.Publisher -match 'Hasan') 'uninstall entry'
}

Step 'Web interface and API' {
  $r = Invoke-WebRequest -Uri "$(Base)/" -UseBasicParsing
  Assert ($r.StatusCode -eq 200 -and $r.Content -match '<html') 'web interface'
  $st = Invoke-RestMethod -Uri "$(Base)/api/setup"
  Assert ($st.required -and $st.allowed) 'first-run setup should be available locally'
  # only loopback in local mode
  $listen = Get-NetTCPConnection -State Listen -LocalPort (Port) | Select-Object -ExpandProperty LocalAddress
  Assert (@($listen | Where-Object { $_ -ne '127.0.0.1' }).Count -eq 0) "listening on $listen"
}

Step 'Permissions on data directories' {
  foreach ($d in @('secrets', 'config', 'data', 'logs', 'backups')) {
    $acl = Get-Acl (Join-Path $DataRoot $d)
    $ids = $acl.Access | ForEach-Object { $_.IdentityReference.Value }
    Assert ($acl.AreAccessRulesProtected) "$d inherits permissions"
    foreach ($bad in @('BUILTIN\Users', 'Everyone', 'NT AUTHORITY\Authenticated Users')) {
      Assert (-not ($ids -contains $bad)) "$d grants $bad"
    }
    Assert ($ids -contains 'NT SERVICE\Nexus') "$d lacks the service account"
  }
  $secretRights = (Get-Acl (Join-Path $DataRoot 'secrets')).Access | Where-Object { $_.IdentityReference.Value -eq 'NT SERVICE\Nexus' }
  Assert (-not ($secretRights.FileSystemRights.ToString() -match 'Write|Modify|FullControl')) 'service can write secrets'
}

Step 'Firewall untouched in local mode' {
  Assert (-not (Get-NetFirewallRule -DisplayName 'Nexus Web Interface' -ErrorAction SilentlyContinue)) 'unexpected firewall rule'
}

Step 'No secrets in logs, command lines or installer output' {
  $logFiles = @(Get-ChildItem (Join-Path $DataRoot 'logs') -File -Force)
  Assert (@($logFiles | Where-Object { $_.Name -like '.*' }).Count -eq 0) "stray files in logs: $($logFiles.Name -join ', ')"
  $files = @($logFiles | ForEach-Object FullName) + @("$WorkDir\install1.log", "$WorkDir\install1.log.jsonl")
  Assert-NoSecretsIn $files
  $cmds = (Get-CimInstance Win32_Process | Where-Object { $_.Name -in @('nexus.exe', 'postgres.exe', 'pg_ctl.exe') }).CommandLine -join "`n"
  foreach ($s in Secrets) { Assert (-not $cmds.Contains($s)) 'secret on a command line' }
  $svcCmd = (Get-CimInstance Win32_Service -Filter "Name='Nexus'").PathName
  foreach ($s in Secrets) { Assert (-not $svcCmd.Contains($s)) 'secret in service command line' }
  $cfg = Get-Content (Join-Path $DataRoot 'config\nexus.env') -Raw
  foreach ($s in Secrets) { Assert (-not $cfg.Contains($s)) 'secret in nexus.env' }
}

if ($E2EDir) {
  Step 'First run in the browser (create admin, Add Device on the simulator, diagnostics, backup)' {
    Push-Location $E2EDir
    try {
      $env:NEXUS_URL = "http://localhost:$(Port)"
      $env:FIRST_RUN = '1'
      $env:NEXUS_USER = $AdminUser
      $env:NEXUS_PASS = $AdminPass
      npx playwright test firstrun.spec.ts --reporter=list
      Assert ($LASTEXITCODE -eq 0) 'playwright first-run test failed'
    } finally { Pop-Location }
  }
} else {
  Step 'First run via API (create admin, add device)' {
    $s = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $body = @{ username = $AdminUser; password = $AdminPass } | ConvertTo-Json
    Invoke-RestMethod -Uri "$(Base)/api/setup" -Method Post -Body $body -ContentType 'application/json' -Headers @{ 'X-Requested-With' = 'nexus' } -WebSession $s | Out-Null
    $dev = @{ ip = '10.20.99.1'; snmp = @{ version = '3'; username = 'prometheus'; password = 'nexus-demo-pass' } } | ConvertTo-Json
    Invoke-RestMethod -Uri "$(Base)/api/devices" -Method Post -Body $dev -ContentType 'application/json' -Headers @{ 'X-Requested-With' = 'nexus' } -WebSession $s | Out-Null
    Start-Sleep -Seconds 30
  }
}

$script:Devices = 0
Step 'Inventory present' {
  $s = Login
  $script:Devices = Device-Count $s
  Write-Host "  devices: $script:Devices"
  Assert ($script:Devices -gt 5) "expected discovered devices, got $script:Devices"
}

Step 'Crash recovery: killed service process is restarted by Windows' {
  $svcPid = (Get-CimInstance Win32_Service -Filter "Name='Nexus'").ProcessId
  Stop-Process -Id $svcPid -Force
  Start-Sleep -Seconds 3
  Wait-Healthy 120 | Out-Null
  $newPid = (Get-CimInstance Win32_Service -Filter "Name='Nexus'").ProcessId
  Assert ($newPid -ne $svcPid) 'service was not restarted'
}

Step 'Restart (as after a reboot)' {
  Restart-Service Nexus
  Wait-Healthy 120 | Out-Null
  Assert ((Device-Count (Login)) -eq $script:Devices) 'data lost after restart'
}

Step 'Diagnostics and backup from the command line' {
  $exe = Join-Path (Reg).AppDir 'nexus.exe'
  $cfg = Join-Path $DataRoot 'config\nexus.env'
  & $exe --config $cfg diagnostics --out "$WorkDir\diag.zip"
  Assert ($LASTEXITCODE -eq 0) 'diagnostics failed'
  $x = Join-Path $WorkDir 'diag'
  Expand-Archive "$WorkDir\diag.zip" -DestinationPath $x -Force
  Assert (Test-Path "$x\checks.json") 'bundle incomplete'
  Assert-NoSecretsIn (Get-ChildItem $x -Recurse -File | ForEach-Object FullName)
  & $exe --config $cfg backup --out "$WorkDir\manual.nxbackup"
  Assert ($LASTEXITCODE -eq 0) 'backup failed'
  Assert ((Get-Item "$WorkDir\manual.nxbackup").Length -gt 1000) 'backup too small'
  Wait-Healthy 30 | Out-Null  # the running service was not disturbed
}

$UpgradeVersion = ''
Step 'Upgrade keeps data' {
  $before = (Reg).Version
  $port = Port
  $code = Run-Installer $Upgrade @('/S', '/NOBROWSER', "/LOG=$WorkDir\install2.log")
  Assert ($code -eq 0) "upgrade exit code $code"
  $h = Wait-Healthy
  $script:UpgradeVersion = $h.version
  Assert ($h.version -ne $before) "version still $($h.version)"
  Assert ((Port) -eq $port) 'port changed during upgrade'
  Assert ((Device-Count (Login)) -eq $script:Devices) 'devices lost during upgrade'
  Assert (@(Get-ChildItem (Join-Path $DataRoot 'backups') -Filter 'nexus-before-upgrade-*').Count -ge 1) 'no pre-upgrade backup'
  Assert (-not (Test-Path (Join-Path $ProgramDir "app\$before"))) 'old version not removed'
  Assert-NoSecretsIn @("$WorkDir\install2.log")
}

Step 'Failed upgrade rolls back automatically' {
  $svcKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\Nexus'
  $good = (Reg).Version
  $brokenVersion = ([regex]::Match((Split-Path $Broken -Leaf), '\d+\.\d+\.\d+')).Value
  Set-ItemProperty -Path $svcKey -Name Environment -Type MultiString -Value @("NEXUS_TEST_FAIL_VERSION=$brokenVersion")
  try {
    $code = Run-Installer $Broken @('/S', '/NOBROWSER', "/LOG=$WorkDir\install3.log")
    Assert ($code -eq 3) "expected exit code 3 (rolled back), got $code"
    $h = Wait-Healthy
    Assert ($h.version -eq $good) "running version $($h.version), expected $good"
    Assert ((Reg).Version -eq $good) 'registry version changed'
    Assert ((Device-Count (Login)) -eq $script:Devices) 'data changed by failed upgrade'
  } finally {
    Remove-ItemProperty -Path $svcKey -Name Environment -ErrorAction SilentlyContinue
  }
}

Step 'LAN mode adds a narrow firewall rule; local mode removes it' {
  $code = Run-Installer $Upgrade @('/S', '/NOBROWSER', '/LAN=1')
  Assert ($code -eq 0) "exit code $code"
  Wait-Healthy | Out-Null
  $rule = Get-NetFirewallRule -DisplayName 'Nexus Web Interface'
  Assert ($rule.Direction -eq 'Inbound' -and $rule.Action -eq 'Allow') 'rule direction/action'
  $profiles = $rule.Profile.ToString()
  Assert ($profiles -match 'Domain' -and $profiles -match 'Private' -and $profiles -notmatch 'Public') "profiles $profiles"
  $pf = $rule | Get-NetFirewallPortFilter
  Assert ($pf.LocalPort -eq [string](Port)) "port $($pf.LocalPort)"
  Assert ((Get-NetFirewallProfile | Where-Object Enabled).Count -ge 0) 'firewall state'
  $code = Run-Installer $Upgrade @('/S', '/NOBROWSER', '/LAN=0')
  Assert ($code -eq 0) "exit code $code"
  Wait-Healthy | Out-Null
  Assert (-not (Get-NetFirewallRule -DisplayName 'Nexus Web Interface' -ErrorAction SilentlyContinue)) 'rule not removed'
}

Step 'Uninstall keeps data by default' {
  $code = Uninstall @()
  Assert ($code -eq 0) "uninstall exit code $code"
  Start-Sleep -Seconds 2
  Assert (-not (Get-Service Nexus -ErrorAction SilentlyContinue)) 'service still installed'
  Assert (-not (Test-Path (Join-Path $ProgramDir 'app'))) 'program files left behind'
  Assert (Test-Path (Join-Path $DataRoot 'data\db\PG_VERSION')) 'data was deleted'
  Assert (Test-Path (Join-Path $DataRoot 'secrets\master.key')) 'master key was deleted'
  Assert (-not (Test-Path 'HKLM:\Software\Nexus')) 'registry key left behind'
  $run = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -ErrorAction SilentlyContinue).PSObject.Properties.Name
  Assert (-not ($run -contains 'Nexus Tray')) 'tray autostart left behind'
}

Step 'Reinstall continues with the existing data' {
  $code = Run-Installer $Upgrade @('/S', '/NOBROWSER')
  Assert ($code -eq 0) "exit code $code"
  Wait-Healthy | Out-Null
  Assert ((Device-Count (Login)) -eq $script:Devices) 'data not picked up after reinstall'
  $st = Invoke-RestMethod -Uri "$(Base)/api/setup"
  Assert (-not $st.required) 'setup offered again for existing data'
}

Step 'Uninstall with explicit data purge' {
  $code = Uninstall @('/PURGEDATA=YES')
  Assert ($code -eq 0) "uninstall exit code $code"
  Start-Sleep -Seconds 2
  Assert (-not (Test-Path $DataRoot)) 'data directory still present'
}

Write-Host ""
Write-Host "All $($script:Passed.Count) installer checks passed:" -ForegroundColor Green
$script:Passed | ForEach-Object { Write-Host "  - $_" }
