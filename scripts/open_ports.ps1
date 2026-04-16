# open_ports.ps1 - PowerShell script to open NMS ports in Windows Firewall
# Run this script AS ADMINISTRATOR on the SERVER machine.

$ports = @(
    @{ Name="NMS Telemetry (UDP)"; Port=9000; Protocol="UDP" },
    @{ Name="NMS Control (TCP)"; Port=9001; Protocol="TCP" },
    @{ Name="NMS Dashboard (TCP)"; Port=5000; Protocol="TCP" }
)

Write-Host "Configuring Windows Firewall for Network Monitoring System..." -ForegroundColor Cyan

foreach ($p in $ports) {
    $ruleName = $p.Name
    $port = $p.Port
    $protocol = $p.Protocol

    # Check if rule exists
    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Host "Rule '$ruleName' already exists. Skipping." -ForegroundColor Yellow
    } else {
        Write-Host "Adding rule: $ruleName (Port $port, $protocol)" -ForegroundColor Green
        New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow -Protocol $protocol -LocalPort $port
    }
}

Write-Host "Firewall configuration complete!" -ForegroundColor Cyan
Write-Host "You can now run the server and connect from other systems."
