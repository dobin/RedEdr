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
        ".\x64\Debug\RedEdrTester.exe 3 $($notepadProcessPid) &"
        #"timeout /t 3 &",  # Wait for 5 seconds
        #"taskkill /im notepad.exe /f"  # Kill notepad.exe
    )
    Start-Process -Wait "C:\rededr\rededr.exe" -ArgumentList "--web --hide --dllreader --trace otepad"
    Stop-Process -Name notepad -Force -ErrorAction SilentlyContinue
}
elseif ($arg -eq "kernel") {
    Start-Process cmd -ArgumentList @(
        "/c",
        "timeout /t 2 &",
        "start notepad.exe &",
        "timeout /t 3 &",
        "taskkill /im notepad.exe /f"
    )
    Start-Process -Wait "C:\rededr\rededr.exe"  -ArgumentList "--hide --kernel --inject --trace otepad"
}
elseif ($arg -eq "etw") {
    Start-Process cmd -ArgumentList @(
        "/c",
        "timeout /t 2 &",
        "start notepad.exe &",
        "timeout /t 3 &",
        "taskkill /im notepad.exe /f"
    )
    Start-Process -Wait "C:\rededr\rededr.exe"  -ArgumentList "--etw --trace otepad"
}
elseif ($arg -eq "etwti") {
    Start-Process cmd -ArgumentList @(
        "/c",
        "timeout /t 2 &",
        'start C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe &',
        "timeout /t 3 &",
        "taskkill /im msedge.exe /f"
    )
    Start-Process -Wait "C:\rededr\rededr.exe"  -ArgumentList "--etwti --trace otepad"
}