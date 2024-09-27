param(
    [string]$arg = $args[0]  # Default to the first argument if not provided
)

if ($arg -eq "dll") {
    # Start notepad.exe in the background
    Start-Process notepad
    Start-Sleep -Seconds 1

    $notepadProcess = Get-Process notepad
    $notepadProcessPid = $notepadProcess.Id

    Start-Process cmd -ArgumentList @(
        "/c",
        "timeout /t 1 &"
        ".\x64\Debug\RedEdrTester.exe 3 $($notepadProcessPid) &",
        "timeout /t 3 &",  # Wait for 5 seconds
        "taskkill /im notepad.exe /f"  # Kill notepad.exe
    )

    # Run the DLL reader
    Start-Process -Wait "C:\rededr\rededr.exe" -ArgumentList "--dllreader --trace Notepad"

    # Kill any remaining notepad process if it exists
    Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue
}
elseif ($arg -eq "kernel") {
    # Start a new cmd session and pass the script inside it, split into multiple lines
    Start-Process cmd -ArgumentList @(
        "/c",
        "timeout /t 2 &",
        "start notepad.exe &",
        "timeout /t 3 &",
        "taskkill /im notepad.exe /f"
    )

    # Run the kernel trace
    Start-Process "C:\rededr\rededr.exe"  -ArgumentList "--kernel --trace Notepad"
}