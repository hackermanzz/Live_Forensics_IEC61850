# restart_all_pis_svgoosepublisher.ps1
#
# Restarts goose_publisher and sv_subscriber on every active Raspberry Pi
# using password-based SSH via the Posh-SSH module.
#
# Run:
#   powershell -ExecutionPolicy Bypass -File .\restart_all_pis_svgoosepublisher.ps1

$PiUser     = "pi"
$PiPassword = "pi"      # <-- CHANGE THIS

# Install Posh-SSH if required
if (-not (Get-Module -ListAvailable -Name Posh-SSH)) {
    Write-Host "Installing Posh-SSH..."
    Install-Module Posh-SSH -Scope CurrentUser -Force
}

Import-Module Posh-SSH

# Build credential
$SecurePassword = ConvertTo-SecureString $PiPassword -AsPlainText -Force
$Credential     = New-Object System.Management.Automation.PSCredential($PiUser, $SecurePassword)

# Active IEDs
$IEDs = @(
    @{IED=1;  IP="192.168.0.8"},
    @{IED=2;  IP="192.168.0.9"},
    @{IED=3;  IP="192.168.0.10"},
    @{IED=4;  IP="192.168.0.11"},
    @{IED=5;  IP="192.168.0.12"},
    @{IED=6;  IP="192.168.0.13"},
    @{IED=8;  IP="192.168.0.15"},
    @{IED=9;  IP="192.168.0.16"},
    @{IED=10; IP="192.168.0.17"},
    @{IED=11; IP="192.168.0.18"},
    @{IED=12; IP="192.168.0.19"},
    @{IED=13; IP="192.168.0.20"},
    @{IED=14; IP="192.168.0.21"}
)

foreach ($Pi in $IEDs)
{
    $Bus = $Pi.IED
    $IP  = $Pi.IP

    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host "IED $Bus ($IP)"
    Write-Host "==================================================" -ForegroundColor Cyan

    $Session = $null

    try
    {
        $Session = New-SSHSession `
            -ComputerName $IP `
            -Credential $Credential `
            -AcceptKey `
            -Force `
            -ConnectionTimeout 10 `
            -ErrorAction Stop

        $RemoteCommand = @"
echo '$PiPassword' | sudo -S pkill -9 sv_subscriber 2>/dev/null || true
echo '$PiPassword' | sudo -S pkill -9 goose_publisher 2>/dev/null || true

sleep 2

cd /home/pi/libiec61850-1.5.1/examples/goose_publisher
echo '$PiPassword' | sudo -S nohup ./goose_publisher_example eth0 > goose_output.log 2>&1 &

sleep 1

cd /home/pi/libiec61850-1.5.1/examples/sv_subscriber
echo '$PiPassword' | sudo -S nohup ./sv_subscriber eth0 $Bus > sv_output.log 2>&1 &

sleep 2

echo
echo "========= PROCESS STATUS ========="

echo
echo "goose_publisher:"
pgrep -a goose_publisher || echo "Not running"

echo
echo "sv_subscriber:"
pgrep -a sv_subscriber || echo "Not running"

echo
echo "Restart complete."
"@

        $Result = Invoke-SSHCommand `
            -SSHSession $Session `
            -Command $RemoteCommand `
            -TimeOut 60

        if ($Result.ExitStatus -eq 0)
        {
            Write-Host "SUCCESS" -ForegroundColor Green

            if ($Result.Output)
            {
                $Result.Output | ForEach-Object { Write-Host $_ }
            }
        }
        else
        {
            Write-Host "FAILED (Exit $($Result.ExitStatus))" -ForegroundColor Red

            if ($Result.Error)
            {
                Write-Host $Result.Error
            }
        }
    }
    catch
    {
        Write-Host "FAILED: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally
    {
        if ($Session)
        {
            Remove-SSHSession -SSHSession $Session | Out-Null
        }
    }
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "Finished restarting all Raspberry Pis."
Write-Host "==================================================" -ForegroundColor Green

