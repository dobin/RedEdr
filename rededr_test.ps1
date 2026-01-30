# RedEdr Test Script
# Starts RedEdr, traces procexp64.exe, then cleans up

$rededrPath = "C:\RedEdr\RedEdr.exe"
#$targetPath = "D:\toolz\procexp64.exe"
$targetPath = "D:\hacking\some_malware\mimikatz.exe"
#$targetPath = "D:\hacking\malware\cs2025-stageless.exe"
$webserverUrl = "http://localhost:8081"

# Start RedEdr in the background
#Write-Host "Starting RedEdr..."
#$rededrProcess = Start-Process -FilePath $rededrPath -PassThru

# Wait for the webserver to be ready
#Write-Host "Waiting for webserver to start..."
#Start-Sleep -Seconds 3

# Call /api/trace/start to start tracing
# Extract filename without path from targetPath
$targetFilename = [System.IO.Path]::GetFileName($targetPath)
Write-Host "Starting trace for $targetFilename..."
$traceBody = @{
    trace = @($targetFilename)
} | ConvertTo-Json

try {
    Invoke-RestMethod -Uri "$webserverUrl/api/trace/start" -Method Post -Body $traceBody -ContentType "application/json"
    Write-Host "Trace started successfully"
} catch {
    Write-Host "Failed to start trace: $_"
}

# Start target executable and wait for it to exit
Write-Host "Starting $targetFilename..."
$procexpProcess = Start-Process -FilePath $targetPath -PassThru
Write-Host "$targetFilename PID: $($procexpProcess.Id) (0x$($procexpProcess.Id.ToString('X')))"
$procexpProcess | Wait-Process

# Call /api/trace/reset to reset the trace
Write-Host "Resetting trace..."
try {
    Invoke-RestMethod -Uri "$webserverUrl/api/trace/stop" -Method Post
    Write-Host "Trace reset successfully"
} catch {
    Write-Host "Failed to reset trace: $_"
}

# Kill RedEdr
#Write-Host "Stopping RedEdr..."
#if ($rededrProcess -and !$rededrProcess.HasExited) {
#    Stop-Process -Id $rededrProcess.Id -Force
#    Write-Host "RedEdr stopped"
#} else {
#    Write-Host "RedEdr process already exited"
#}

