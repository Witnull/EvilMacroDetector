<#
.SYNOPSIS
    Installs and starts the MonitorMalwareService Windows Service.
#>

# Path to Python executable (adjust if using a virtual environment)
$PythonExec = "python"

# Path to the Python service script
$ServiceScript = "C:\Users\null\Downloads\CCMD_DA\MonitorMalwareService.py"

# Install the service
Write-Host "Installing MonitorMalwareService..."
& $PythonExec $ServiceScript install

# Wait briefly to ensure installation completes
Start-Sleep -Seconds 2

# Start the service
Write-Host "Starting MonitorMalwareService..."
& $PythonExec $ServiceScript start

Write-Host "Service installed and started."