# reset_all_ieds_nodered.ps1
# Spams the Node-RED /reset endpoint on selected IEDs until voltage AND current
# stabilise within per-IED thresholds.
# Requires: http in /reset endpoint deployed on each Pi's Node-RED
#
# Usage:
#   Interactive : powershell -ExecutionPolicy Bypass -File ".\reset_all_ieds_nodered.ps1"
#   Single IED  : powershell -ExecutionPolicy Bypass -File ".\reset_all_ieds_nodered.ps1" -Target "3"
#   Multiple    : powershell -ExecutionPolicy Bypass -File ".\reset_all_ieds_nodered.ps1" -Target "1,2,3"
#   All at once : powershell -ExecutionPolicy Bypass -File ".\reset_all_ieds_nodered.ps1" -Target "all"
#   Custom delay: powershell -ExecutionPolicy Bypass -File ".\reset_all_ieds_nodered.ps1" -Target "all" -Delay 1000
#
# NOTE: Minimum -Delay is 1000ms (Node-RED timestamp fires every 1 second).

param(
    [string]$Target = "",
    [int]$Delay     = 1000
)

$SharedFolder        = "C:\Users\A102350\Desktop\SharedFolder"
$CycleDelay          = [math]::Max($Delay, 1000)
$MaxCycles           = 100
$StableReadsRequired = 10

# --- SSH / full-recovery config ---
$RecoveryMode  = $false
$VMUser        = "hello2"      # SSH user on the VM running GOOSE
$VMHost        = "192.168.0.32"      # VM host / IP
$SshTarget     = "$VMUser@$VMHost"
# Password auth. Leave blank to be prompted once at runtime (recommended);
# hard-coding a plaintext password here is lab-only. Assumes the sudo password
# is the same as the SSH password (fed to sudo -S by the helper).
$VMPassword    = "hello2"
# NOTE: the kill command targets goose_subscriber, though the flow calls it the
#       "publisher" - confirm which process you actually mean to stop.
# Bare commands (NO leading sudo): the helper runs each via `sudo -S`.
# Single-quoted so $(...) is evaluated on the VM, not locally by PowerShell.
$GooseStopCmd  = 'kill -9 $(pgrep -f goose_subscriber)'
$GooseStartCmd = 'nohup /home/hello2/Downloads/libiec61850-1.5/examples/goose_subscriber/goose_subscriber_example enp0s3 >/tmp/goose_sub_output.log 2>&1 &' # command to relaunch it (needed for Phase 4)
$SettleWait    = 60                # seconds to wait between recovery phases
# Switch-on: no endpoint exists yet, so Phase 3 prompts you to flip switches
# manually. Once you put an http-in node in front of your
# global.set('switch', msg.payload) function, set these and it goes automatic.
$SwitchEndpointFmt = "http://{0}:1880/switch"        # per-IED switch URL, {0} = IP e.g. "http://{0}:1880/switch"
$ScadaSwitchUri    = "http://192.168.0.25:1880/switch_all_on"            # SCADA main-switch URL
# Switches are currently hardcoded to 1 in the Node-RED CB Decision function and
# SCADA is down, so Phase 3 has nothing to toggle. Set $false when SCADA is back
# and the switch is driven by global state again.
$SwitchesHardcodedOn = $false
# Password-based SSH via the Posh-SSH module (installed automatically if missing).

# IEDTable: per-IED IP, SV file, and thresholds matching Node-RED CB Decision exactly
# OV=overvoltage  UV=undervoltage  OC=overcurrent  UC=undercurrent
$IEDTable = @{
    1  = @{ IP="192.168.0.8";  SvFile="sv_ied1.txt";  OVThreshold=300000; UVThreshold=200;  OCThreshold=6000; UCThreshold=0.5; InUse=$true  }
    2  = @{ IP="192.168.0.9";  SvFile="sv_ied2.txt";  OVThreshold=400000; UVThreshold=200;  OCThreshold=6000; UCThreshold=0.5; InUse=$true  }
    3  = @{ IP="192.168.0.10"; SvFile="sv_ied3.txt";  OVThreshold=600000; UVThreshold=200;  OCThreshold=6000; UCThreshold=0.5; InUse=$true  }
    4  = @{ IP="192.168.0.11"; SvFile="sv_ied4.txt";  OVThreshold=30000;  UVThreshold=200;  OCThreshold=6000; UCThreshold=0.5; InUse=$true  }
    5  = @{ IP="192.168.0.12"; SvFile="sv_ied5.txt";  OVThreshold=30000;  UVThreshold=200;  OCThreshold=6000; UCThreshold=0.5; InUse=$true  }
    6  = @{ IP="192.168.0.13"; SvFile="sv_ied6.txt";  OVThreshold=30000;  UVThreshold=200;  OCThreshold=6000; UCThreshold=0.5; InUse=$true  }
    7  = @{ IP="192.168.0.14"; SvFile="sv_ied7.txt";  OVThreshold=30000;  UVThreshold=200;  OCThreshold=6000; UCThreshold=0.5; InUse=$false }
    8  = @{ IP="192.168.0.15"; SvFile="sv_ied8.txt";  OVThreshold=30000;  UVThreshold=200;  OCThreshold=6000; UCThreshold=0.5; InUse=$true  }
    9  = @{ IP="192.168.0.16"; SvFile="sv_ied9.txt";  OVThreshold=30000;  UVThreshold=200;  OCThreshold=6000; UCThreshold=0.5; InUse=$true  }
    10 = @{ IP="192.168.0.17"; SvFile="sv_ied10.txt"; OVThreshold=30000;  UVThreshold=200;  OCThreshold=6000; UCThreshold=0.5; InUse=$true  }
    11 = @{ IP="192.168.0.18"; SvFile="sv_ied11.txt"; OVThreshold=135000; UVThreshold=0.5;  OCThreshold=4000; UCThreshold=0.5; InUse=$true  }
    12 = @{ IP="192.168.0.19"; SvFile="sv_ied12.txt"; OVThreshold=135000; UVThreshold=0.5;  OCThreshold=4000; UCThreshold=0.5; InUse=$true  }
    13 = @{ IP="192.168.0.20"; SvFile="sv_ied13.txt"; OVThreshold=135000; UVThreshold=0.5;  OCThreshold=4000; UCThreshold=0.5; InUse=$true  }
    14 = @{ IP="192.168.0.21"; SvFile="sv_ied14.txt"; OVThreshold=135000; UVThreshold=0.5;  OCThreshold=4000; UCThreshold=0.5; InUse=$true  }
}

# Reads all 6 pipe-separated values: Va|Vb|Vc|Ia|Ib|Ic
function Get-SvValues([string]$svFilePath) {
    try {
        $parts = ((Get-Content $svFilePath -Raw).Trim() -split "\|")
        if ($parts.Count -lt 6) { return $null }
        return @([double]$parts[0],[double]$parts[1],[double]$parts[2],
                 [double]$parts[3],[double]$parts[4],[double]$parts[5])
    } catch { return $null }
}

# Returns list of out-of-band field names e.g. "Va OV", "Ia UC"
# Empty list = all values in normal range
function Get-Offenders($vals, $ovT, $uvT, $ocT, $ucT) {
    $vn=@("Va","Vb","Vc"); $in=@("Ia","Ib","Ic"); $bad=@()
    for ($k=0; $k -lt 3; $k++) {
        if     ($vals[$k]   -gt $ovT) { $bad += "$($vn[$k]) OV" }
        elseif ($vals[$k]   -lt $uvT) { $bad += "$($vn[$k]) UV" }
    }
    for ($k=0; $k -lt 3; $k++) {
        if     ($vals[$k+3] -gt $ocT) { $bad += "$($in[$k]) OC" }
        elseif ($vals[$k+3] -lt $ucT) { $bad += "$($in[$k]) UC" }
    }
    return $bad
}

function Invoke-IEDReset([string]$ip) {
    try {
        Invoke-RestMethod -Uri "http://$ip`:1880/reset" -Method GET -TimeoutSec 3 | Out-Null
        return "OK"
    } catch { return "FAILED" }
}

# Returns the VM credential, prompting once for the password if not configured.
function Get-VMCredential {
    if ($script:VMCred) { return $script:VMCred }
    if ($VMPassword -ne "") {
        $sec = ConvertTo-SecureString $VMPassword -AsPlainText -Force
    } else {
        $sec = Read-Host "  SSH password for $SshTarget" -AsSecureString
    }
    $script:VMCred = New-Object System.Management.Automation.PSCredential($VMUser, $sec)
    return $script:VMCred
}

# Runs a command on the VM over SSH (password auth via Posh-SSH), elevating with
# sudo -S using the same password so it doesn't block on sudo's own prompt.
function Invoke-VMCommand([string]$cmd, [string]$label) {
    Write-Host "  SSH ($label): $cmd"

    if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
        try {
            Write-Host "    Installing Posh-SSH module (one-time)..."
            Install-Module Posh-SSH -Scope CurrentUser -Force -ErrorAction Stop
        } catch {
            Write-Host "    FAILED - Posh-SSH unavailable and could not be installed: $($_.Exception.Message)"
            return $false
        }
    }
    Import-Module Posh-SSH -ErrorAction SilentlyContinue

    $session = $null
    try {
        $cred = Get-VMCredential
        $pw   = $cred.GetNetworkCredential().Password
        $session = New-SSHSession -ComputerName $VMHost -Credential $cred -AcceptKey -Force -ConnectionTimeout 10 -ErrorAction Stop

        # -S reads the sudo password from stdin; -p '' suppresses the prompt text.
        $remote = "echo '$pw' | sudo -S -p '' $cmd"
        $res = Invoke-SSHCommand -SSHSession $session -Command $remote -TimeOut 20 -ErrorAction Stop

        if ($res.ExitStatus -eq 0) {
            Write-Host "    OK"
            return $true
        }
        Write-Host "    FAILED (exit $($res.ExitStatus)): $($res.Error) $($res.Output)"
        return $false
    } catch {
        Write-Host "    FAILED: $($_.Exception.Message)"
        return $false
    } finally {
        if ($session) { Remove-SSHSession -SSHSession $session | Out-Null }
    }
}

# Writes "1" with NO trailing newline to each in-use IED's cb_status file, so
# MATLAB's last-byte read sees the CB-closed command rather than a stray CRLF.
function Set-AllCBClosed($iedList) {
    foreach ($n in $iedList) {
        $p = "$SharedFolder\cb_status_ied$n.txt"
        try {
            [System.IO.File]::WriteAllText($p, "1")
            Write-Host "    cb_status_ied$n.txt = 1"
        } catch {
            Write-Host "    FAILED writing $p : $($_.Exception.Message)"
        }
    }
}

# Turns on the main switch on each IED and the SCADA. Falls back to a manual
# prompt when no switch endpoint is configured.
function Invoke-SwitchOn($iedList) {
    if ($SwitchEndpointFmt -ne "") {
        foreach ($n in $iedList) {
            $uri = [string]::Format($SwitchEndpointFmt, $IEDTable[$n].IP)
            try {
                Invoke-WebRequest -Uri $uri -Method GET -TimeoutSec 5 -UseBasicParsing | Out-Null
                Write-Host "    IED$n switch ON"
            } catch {
                Write-Host "    IED$n switch FAILED ($uri)"
            }
        }
        if ($ScadaSwitchUri -ne "") {
            try {
                Invoke-WebRequest -Uri $ScadaSwitchUri -Method GET -TimeoutSec 5 -UseBasicParsing | Out-Null
                Write-Host "    SCADA switch ON"
            } catch {
                Write-Host "    SCADA switch FAILED"
            }
        }
    } else {
        Write-Host "    No switch endpoint configured - manual step:"
        Write-Host "    Turn ON the main switch on each IED and on the SCADA now."
        Read-Host "    Press Enter once all switches are ON"
    }
}

# ---- USER SELECTION ----

Write-Host ""
Write-Host "============================================"
Write-Host "  IED Reset Spam Tool"
Write-Host "  Checks: Va Vb Vc Ia Ib Ic against per-IED thresholds"
Write-Host "  SharedFolder : $SharedFolder"
Write-Host "  Cycle delay  : $CycleDelay ms"
Write-Host "  Max cycles   : $MaxCycles"
Write-Host "  IED7 skipped (not in use)"
Write-Host "============================================"
Write-Host ""

$validIEDs = ($IEDTable.Keys | Where-Object { $IEDTable[$_].InUse } | Sort-Object)

if ($Target -eq "") {
    Write-Host "Available IEDs: $($validIEDs -join ', ')"
    Write-Host ""
    Write-Host "Enter target IED(s):"
    Write-Host "  Single       : 3"
    Write-Host "  Multiple     : 1,2,3"
    Write-Host "  All at once  : all"
    Write-Host "  Full recovery: recovery   (SSH stop GOOSE -> force CB=1 -> switches -> stabilise -> restart GOOSE)"
    Write-Host ""
    $Target = (Read-Host "Your choice").Trim()
}

$selectedIEDs = @()
if ($Target.ToLower() -eq "all") {
    $selectedIEDs = $validIEDs
} elseif ($Target.ToLower() -eq "recovery") {
    $RecoveryMode = $true
    $selectedIEDs = $validIEDs
} else {
    foreach ($p in ($Target -split ",")) {
        $num = $p.Trim()
        if ($num -match "^\d+$") {
            $n = [int]$num
            if ($IEDTable.ContainsKey($n)) {
                if ($IEDTable[$n].InUse) { $selectedIEDs += $n }
                else { Write-Host "  IED$n not in use - skipping" }
            } else { Write-Host "  IED$n not in table - skipping" }
        }
    }
}

if ($selectedIEDs.Count -eq 0) {
    Write-Host "No valid IEDs selected."
    Read-Host "Press Enter to exit"
    exit 1
}

$selectedIEDs = $selectedIEDs | Sort-Object
Write-Host "Selected: IED $($selectedIEDs -join ', ')"
Write-Host ""

# ============================================================
# FULL RECOVERY SEQUENCE - Phases 1-3a (stabilise = Phase 3b, reuses parallel mode below)
# ============================================================

if ($RecoveryMode) {
    Write-Host "============================================"
    Write-Host "  FULL RECOVERY SEQUENCE"
    Write-Host "  IEDs: $($selectedIEDs -join ', ')"
    Write-Host "  VM  : $SshTarget"
    Write-Host "============================================"
    Write-Host ""

    # Phase 1 - stop GOOSE on the VM, let traffic drain
    Write-Host "[Phase 1] Stopping GOOSE on VM..."
    Invoke-VMCommand $GooseStopCmd "stop GOOSE" | Out-Null
    Write-Host "  Waiting $SettleWait s..."
    Start-Sleep -Seconds 10
    Write-Host ""

    # Phase 2 - force all CBs closed, let MATLAB settle, then re-check
    Write-Host "[Phase 2] Forcing all CB status files to 1..."
    Set-AllCBClosed $selectedIEDs
    Write-Host "  Waiting $SettleWait s for MATLAB/Simulink to stabilise..."
    Start-Sleep -Seconds $SettleWait
    Write-Host "  Re-checking SV values:"
    foreach ($n in $selectedIEDs) {
        $c    = $IEDTable[$n]
        $vals = Get-SvValues "$SharedFolder\$($c.SvFile)"
        if ($null -ne $vals) {
            $off = Get-Offenders $vals $c.OVThreshold $c.UVThreshold $c.OCThreshold $c.UCThreshold
            $s   = if ($off.Count -eq 0) { "in band" } else { $off -join " " }
            Write-Host ("    IED{0,-3} {1}" -f $n, $s)
        } else {
            Write-Host ("    IED{0,-3} read error" -f $n)
        }
    }
    Write-Host ""

    # Phase 3a - main switches. Currently hardcoded to 1 in the Node-RED CB
    # Decision function with SCADA down, so there is nothing to toggle.
    Write-Host "[Phase 3] Main switches..."
    if ($SwitchesHardcodedOn) {
        Write-Host "  Switches hardcoded ON in Node-RED CB Decision - skipping (SCADA down)."
    } else {
        Invoke-SwitchOn $selectedIEDs
    }
    Write-Host ""
    Write-Host "  Continuing to threshold stabilisation (Phase 3b)..."
    Write-Host ""
}

# ============================================================
# SINGLE IED MODE - live per-cycle output
# ============================================================

if ($selectedIEDs.Count -eq 1 -and -not $RecoveryMode) {
    $n   = $selectedIEDs[0]
    $cfg = $IEDTable[$n]
    $svPath = "$SharedFolder\$($cfg.SvFile)"

    Write-Host "============================================"
    Write-Host "Single IED Mode - IED$n"
    Write-Host "IP        : $($cfg.IP)"
    Write-Host "Reset URL : http://$($cfg.IP):1880/reset"
    Write-Host "SV File   : $svPath"
    Write-Host "V thresh  : UV=$($cfg.UVThreshold)  OV=$($cfg.OVThreshold)"
    Write-Host "I thresh  : UC=$($cfg.UCThreshold)  OC=$($cfg.OCThreshold)"
    Write-Host "============================================"
    Write-Host ""

    Write-Host "Step 1 - Testing reset endpoint..."
    $testResult = Invoke-IEDReset $cfg.IP
    if ($testResult -eq "OK") {
        Write-Host "OK - Endpoint reachable, CB LED should flash green"
    } else {
        Write-Host "FAILED - Cannot reach http://$($cfg.IP):1880/reset"
        Write-Host "  Check Pi on, Node-RED running, /reset endpoint deployed"
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host ""

    Write-Host "Step 2 - Reading initial values from $($cfg.SvFile)..."
    $vals = Get-SvValues $svPath
    if ($null -eq $vals) {
        Write-Host "FAILED - Cannot read $svPath"
        Write-Host "Check SharedFolder path and MATLAB is running"
        Read-Host "Press Enter to exit"
        exit 1
    }
    Write-Host "Va=$([math]::Round($vals[0],2)) Vb=$([math]::Round($vals[1],2)) Vc=$([math]::Round($vals[2],2))"
    Write-Host "Ia=$([math]::Round($vals[3],4)) Ib=$([math]::Round($vals[4],4)) Ic=$([math]::Round($vals[5],4))"
    Write-Host ""

    $off = Get-Offenders $vals $cfg.OVThreshold $cfg.UVThreshold $cfg.OCThreshold $cfg.UCThreshold
    if ($off.Count -eq 0) {
        Write-Host "All values already in normal range - no spam needed"
        Write-Host "If CB still goes to 0, check a different IED"
        Read-Host "Press Enter to exit"
        exit 0
    }
    Write-Host "Out of range: $($off -join ', ')"
    Write-Host ""

    Write-Host "Step 3 - Spamming /reset until Va Vb Vc Ia Ib Ic all stable..."
    Write-Host ""
    Write-Host ("Cycle".PadRight(7) + "Va (V)".PadRight(16) + "Ia (A)".PadRight(12) + "Status".PadRight(26) + "Reset".PadRight(7) + "Trend")
    Write-Host ("-" * 75)

    $cycle=0; $stable=$false; $stableCount=0; $prevV=$vals[0]

    while ($cycle -lt $MaxCycles -and $stable -eq $false) {
        $cycle++
        $rr = Invoke-IEDReset $cfg.IP
        Start-Sleep -Milliseconds $CycleDelay

        $vals = Get-SvValues $svPath
        if ($null -ne $vals) {
            $off     = Get-Offenders $vals $cfg.OVThreshold $cfg.UVThreshold $cfg.OCThreshold $cfg.UCThreshold
            $vstatus = if ($off.Count -eq 0) { "NORMAL" } else { $off -join " " }
            $trend   = if ($vals[0] -lt ($prevV - 100)) { "dropping" }
                       elseif ($vals[0] -gt ($prevV + 100)) { "rising" }
                       else { "holding" }
            Write-Host (([string]$cycle).PadRight(7) +
                ([string][math]::Round($vals[0],2)).PadRight(16) +
                ([string][math]::Round($vals[3],4)).PadRight(12) +
                $vstatus.PadRight(26) +
                $rr.PadRight(7) +
                $trend)
            $prevV = $vals[0]
            if ($off.Count -eq 0) { $stableCount++ } else { $stableCount = 0 }
            if ($stableCount -ge $StableReadsRequired) { $stable = $true }
        } else {
            Write-Host (([string]$cycle).PadRight(7) + "READ ERROR".PadRight(16) + "".PadRight(12) + "".PadRight(26) + $rr)
            $stableCount = 0
        }
    }

    Write-Host ""
    Write-Host "============================================"
    if ($stable) {
        Write-Host "STABLE after $cycle cycles (~$([math]::Round($cycle * $CycleDelay / 1000))s)"
        if ($vals) {
            Write-Host "Final Va=$([math]::Round($vals[0],2)) V  Ia=$([math]::Round($vals[3],4)) A"
        }
        Write-Host "CB should be green on dashboard"
    } else {
        Write-Host "DID NOT STABILISE after $MaxCycles cycles"
        if ($vals) {
            Write-Host "Final Va=$([math]::Round($vals[0],2)) V  Ia=$([math]::Round($vals[3],4)) A"
            $rem = Get-Offenders $vals $cfg.OVThreshold $cfg.UVThreshold $cfg.OCThreshold $cfg.UCThreshold
            if ($rem.Count -gt 0) { Write-Host "Still out of range: $($rem -join ', ')" }
        }
        Write-Host ""
        Write-Host "Check:"
        Write-Host "  1. Thresholds correct? V=$($cfg.UVThreshold)-$($cfg.OVThreshold)  I=$($cfg.UCThreshold)-$($cfg.OCThreshold)"
        Write-Host "  2. MATLAB running and updating $($cfg.SvFile)?"
        Write-Host "  3. GOOSE subscriber updating cb_status_ied$n.txt?"
    }
    Write-Host "============================================"
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 0
}

# ============================================================
# MULTI IED MODE - parallel background jobs
# ============================================================

Write-Host "============================================"
Write-Host "Parallel Mode - $($selectedIEDs.Count) IEDs simultaneously"
Write-Host "============================================"
Write-Host ""

foreach ($n in $selectedIEDs) {
    $cfg = $IEDTable[$n]
    Write-Host ("IED{0,-4} {1,-16} V:{2}/{3}  I:{4}/{5}  {6}" -f `
        $n, $cfg.IP, $cfg.UVThreshold, $cfg.OVThreshold,
        $cfg.UCThreshold, $cfg.OCThreshold, $cfg.SvFile)
}
Write-Host ""
Write-Host "Launching parallel jobs..."
Write-Host ""

$jobs = @()
foreach ($n in $selectedIEDs) {
    $cfg    = $IEDTable[$n]
    $svPath = "$SharedFolder\$($cfg.SvFile)"

    $job = Start-Job -ScriptBlock {
        param($iedNum, $ip, $svPath, $ovT, $uvT, $ocT, $ucT, $maxC, $delay, $stabReq)

        function Get-SvValues([string]$p) {
            try {
                $parts = ((Get-Content $p -Raw).Trim() -split "\|")
                if ($parts.Count -lt 6) { return $null }
                return @([double]$parts[0],[double]$parts[1],[double]$parts[2],
                         [double]$parts[3],[double]$parts[4],[double]$parts[5])
            } catch { return $null }
        }

        function Get-Offenders($v, $ovT, $uvT, $ocT, $ucT) {
            $vn=@("Va","Vb","Vc"); $in=@("Ia","Ib","Ic"); $bad=@()
            for ($k=0;$k-lt 3;$k++) {
                if     ($v[$k]   -gt $ovT) { $bad += "$($vn[$k]) OV" }
                elseif ($v[$k]   -lt $uvT) { $bad += "$($vn[$k]) UV" }
            }
            for ($k=0;$k-lt 3;$k++) {
                if     ($v[$k+3] -gt $ocT) { $bad += "$($in[$k]) OC" }
                elseif ($v[$k+3] -lt $ucT) { $bad += "$($in[$k]) UC" }
            }
            return $bad
        }

        $result = @{ IED=$iedNum; Stable=$false; Cycles=0; FinalV=$null; FinalI=$null; Reason=""; Skipped=$false }

        try {
            Invoke-RestMethod -Uri "http://$ip`:1880/reset" -Method GET -TimeoutSec 3 | Out-Null
        } catch {
            $result.Reason="Endpoint unreachable"; $result.Skipped=$true; return $result
        }

        $vals = Get-SvValues $svPath
        if ($null -eq $vals) {
            $result.Reason="Cannot read SV file"; $result.Skipped=$true; return $result
        }

        $off = Get-Offenders $vals $ovT $uvT $ocT $ucT
        if ($off.Count -eq 0) {
            $result.Stable=$true; $result.FinalV=$vals[0]; $result.FinalI=$vals[3]
            $result.Reason="Already stable"; return $result
        }

        $cycle=0; $stable=$false; $sc=0
        while ($cycle -lt $maxC -and $stable -eq $false) {
            $cycle++
            try { Invoke-RestMethod -Uri "http://$ip`:1880/reset" -Method GET -TimeoutSec 3 | Out-Null } catch {}
            Start-Sleep -Milliseconds $delay
            $vals = Get-SvValues $svPath
            if ($null -ne $vals) {
                $off = Get-Offenders $vals $ovT $uvT $ocT $ucT
                if ($off.Count -eq 0) { $sc++ } else { $sc=0 }
                if ($sc -ge $stabReq) { $stable=$true }
            } else { $sc=0 }
        }

        $result.Stable=$stable; $result.Cycles=$cycle
        $result.FinalV = if ($null -ne $vals) { $vals[0] } else { $null }
        $result.FinalI = if ($null -ne $vals) { $vals[3] } else { $null }
        $result.Reason = if ($stable) { "Stabilised" } else { "Max cycles reached" }
        return $result

    } -ArgumentList $n, $cfg.IP, $svPath,
                    $cfg.OVThreshold, $cfg.UVThreshold,
                    $cfg.OCThreshold, $cfg.UCThreshold,
                    $MaxCycles, $CycleDelay, $StableReadsRequired

    $jobs += @{ Num=$n; IP=$cfg.IP; Job=$job }
    Write-Host "  IED$n ($($cfg.IP)) - started"
}

Write-Host ""
$totalSecs    = [math]::Ceiling($MaxCycles * $CycleDelay / 1000)
$pollInterval = 5
$elapsed      = 0
$allDone      = $false
Write-Host "Waiting up to $totalSecs seconds (parallel - total = slowest IED)..."
Write-Host ""

while (-not $allDone -and $elapsed -lt ($totalSecs + 30)) {
    Start-Sleep -Seconds $pollInterval
    $elapsed  += $pollInterval
    $completed = ($jobs | Where-Object { $_.Job.State -eq "Completed" }).Count
    $running   = ($jobs | Where-Object { $_.Job.State -eq "Running"   }).Count
    Write-Host "  [$elapsed s]  $completed/$($jobs.Count) done,  $running still running..."
    $allDone   = ($running -eq 0)
}

Write-Host ""
Write-Host "============================================"
Write-Host "  RESULTS"
Write-Host "============================================"
Write-Host ""
Write-Host ("IED".PadRight(6)+"IP".PadRight(16)+"Result".PadRight(12)+"Cycles".PadRight(8)+"Final Va".PadRight(14)+"Final Ia".PadRight(12)+"Reason")
Write-Host ("-" * 80)

$allStable = $true
foreach ($j in ($jobs | Sort-Object { $_.Num })) {
    $r = Receive-Job -Job $j.Job -Wait
    Remove-Job -Job $j.Job

    $rs = if ($r.Skipped) { "SKIPPED" } elseif ($r.Stable) { "STABLE" } else { "UNSTABLE" }
    if (-not $r.Stable) { $allStable = $false }

    $fv = if ($null -ne $r.FinalV) { "$([math]::Round($r.FinalV,0)) V" } else { "N/A" }
    $fi = if ($null -ne $r.FinalI) { "$([math]::Round($r.FinalI,4)) A" } else { "N/A" }

    Write-Host (("IED$($r.IED)").PadRight(6)+$j.IP.PadRight(16)+$rs.PadRight(12)+
        ([string]$r.Cycles).PadRight(8)+$fv.PadRight(14)+$fi.PadRight(12)+$r.Reason)
}

Write-Host ""
Write-Host "============================================"
if ($allStable) {
    Write-Host "ALL SELECTED IEDs STABILISED"
    Write-Host "All CBs should be green on dashboards"
} else {
    Write-Host "SOME IEDs DID NOT STABILISE - check table above"
    Write-Host ""
    Write-Host "For unstable IEDs check:"
    Write-Host "  1. Thresholds correct in IEDTable config?"
    Write-Host "  2. MATLAB running and updating sv_ied*.txt?"
    Write-Host "  3. /reset endpoint deployed on that Pi?"
    Write-Host "  4. GOOSE subscriber updating cb_status_ied*.txt?"
}
Write-Host "============================================"

if ($RecoveryMode) {
    Write-Host ""
    Write-Host "[Phase 4] Re-enabling GOOSE on VM..."
    if ($allStable) {
        Write-Host "  All IEDs stable. Waiting $SettleWait s before re-enabling..."
        #Start-Sleep -Seconds $SettleWait
        Start-Sleep -Seconds 5
        Invoke-VMCommand $GooseStartCmd "start GOOSE" | Out-Null
    } else {
        Write-Host "  SKIPPED - not all IEDs stabilised; GOOSE left stopped."
        Write-Host "  Resolve the unstable IEDs above, then start GOOSE manually or re-run."
    }
    Write-Host "============================================"
}

Write-Host ""
Read-Host "Press Enter to exit"
