<#
.SYNOPSIS
    Stops and removes the MonitorMalwareService Windows Service.
#>

# Path to Python executable (adjust if using a virtual environment)
$PythonExec = "python"

# Path to the Python service script
$ServiceScript = "C:\Users\null\Downloads\CCMD_DA\MonitorMalwareService.py"

# Stop the service
Write-Host "Stopping MonitorMalwareService..."
& $PythonExec $ServiceScript stop

# Wait briefly to ensure the service stops
Start-Sleep -Seconds 2

# Remove the service
Write-Host "Removing MonitorMalwareService..."
& $PythonExec $ServiceScript remove

Write-Host "Service stopped and removed."