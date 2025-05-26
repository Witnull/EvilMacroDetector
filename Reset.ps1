Write-Host "Stopping and removing MonitorMalwareService..."
& ./Stop-RemoveService.ps1
# Wait briefly to ensure the service stops
Start-Sleep -Seconds 2

Write-Host "Start MonitorMalwareService..."
& ./Install-StartService.ps1
