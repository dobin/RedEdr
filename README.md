# RedEdr

Display events from Windows to see the detection surface of your malware.

Same data as an EDR sees. 

* Find the telemetry your malware generates
* Verify your anti-EDR techniques work
* Debug and analyze malware


## Implemented Telemetry Consumers

* ETW
  * Microsoft-Windows-Kernel-Process
  * Microsoft-Windows-Security-Auditing
    * needs SYSTEM
    * restrictions apply, see gpedit.msc -> Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies - Local Group Policy object
  * And defender
    * Microsoft-Antimalware-Engine
    * Microsoft-Antimalware-RTP
    * Microsoft-Antimalware-AMFilter
    * Microsoft-Antimalware-Scan-Interface
    * Microsoft-Antimalware-Protection

* Kernel Callbacks
  * PsSetCreateProcessNotifyRoutine
  * PsSetCreateThreadNotifyRoutine
  * PsSetLoadImageNotifyRoutine
  * (ObRegisterCallbacks)

* AMSI ntdll.dll hooking from kernelspace (KAPC from LoadImage callback)
* AMSI ntdll.dll hooking from userspace (ETW based, unreliable)



## Requirements

Use a VM.

To compile the kernel driver: 
* Install WDK (+SDK): https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

Change Windows boot options to enable self-signed kernel drivers:
```
bcdedit /set testsigning on
bcdedit -debug on
```

After compiling solution (all "Debug"), you should have: 
* C:\RedEdr\RedEdr.exe: The userspace component
* C:\RedEdr\RedEdrDriver\*: The kernel module
* C:\RedEdr\RedEdrDll.dll: The injectable DLL (amsi.dll)

Everything should be in `C:\RedEdr`. No other directories are supported.

Execute as admin obviously. 

If you want ETW Microsoft-Windows-Security-Auditing, start as SYSTEM. 


## Usage

RedEdr will trace all processes containing argument 1 in its process image name (exe path). And its children, recursively. 

There are two main modes: 
* With kernel module (kernel callbacks, KAPC DLL injection)
* Without kernel module (ETW, mplog)

I recommend to use it with kernel module. For a quick test, you can use RedEdr without. 
RedEdr only traces newly created processes, with the `--trace` argument in the image
name. After starting RedEdr, just start `notepad.exe`. Make sure you have the right name, 
check with `tasklist | findstr notepad.exe` (could be `Notepad`?).

Only ETW, no kernel module:
```
PS > .\RedEdr.exe --etw --trace notepad.exe
```

Kernel module callbacks and KAPC DLL injection into processes: 
```
PS > .\RedEdr.exe --kernel --inject --trace notepad.exe
```


If you want just the events, without any log output:
```
PS > .\RedEdr.exe ... --trace notepad.exe 2>$null
```

Start with web server returning all event on `http://localhost:8080` as json array:
```
PS > .\RedEdr.exe ... --trace notepad.exe --web
```


## Example Output



# Source

## Solutions

All should be compiled in "Debug" mode. 

RedEdr: 
* ETW reader
* MPLOG reader
* pipe-server for RedEdrDll (`pipe\\RedEdrDllCom`)
* pipe-server for RedEdrDriver (`pipe\\RedEdrKrnCom`)

RedEdrDriver:
* Kernel driver to capture kernel callbacks
* Will do KAPC injection
* connects to RedEdr pipe server to transmit captured data

RedEdrDll: 
* amsi.dll style, to be injected into target processes
* connects to RedEdr pipe server to transmit captured data

RedEdrTester: 
* internal testing tool


## Pipes

* `\\.\pipe\RedEdrDllCom`: injected DLL -> RedEdr server communication
* `\\.\pipe\RedEdrKrnCom`: Kernel server -> RedEdr communication


## Hacking

* https://github.com/dobin/RedEdr/blob/master/RedEdrDriver/kcallbacks.c
* https://github.com/dobin/RedEdr/blob/master/RedEdrDll/dllmain.cpp

* https://github.com/dobin/RedEdr/blob/master/RedEdr/etwreader.cpp
* https://github.com/dobin/RedEdr/blob/master/RedEdr/injecteddllreader.cpp
* https://github.com/dobin/RedEdr/blob/master/RedEdr/kernelreader.cpp


## Todo

More consumers:
* ETW-TI
* Kernel ETW?
* Kernel minifilter?
* AMSI provider


## Based on

Based on MyDumbEdr
* GPLv3
* https://sensepost.com/blog/2024/sensecon-23-from-windows-drivers-to-an-almost-fully-working-edr/
* https://github.com/sensepost/mydumbedr
* patched https://github.com/dobin/mydumbedr
* which seems to use: https://github.com/CCob/SylantStrike/tree/master/SylantStrike

With KAPC injection from:
* https://github.com/0xOvid/RootkitDiaries/



## Example Output

```
C:\Windows\system32>c:\rededr\rededr.exe --trace notepad --kernel --inject --etw
2024-08-18 22:13:00.682 INFO| --( RedEdr 0.2
2024-08-18 22:13:00.683 INFO| --( Tracing process name notepad and its children
2024-08-18 22:13:00.684 INFO| --[ Enable SE_DEBUG: OK
2024-08-18 22:13:00.684 INFO| --( Input: ETW Reader
2024-08-18 22:13:00.684 INFO| --[ Tracing session name: RedEdrEtw
2024-08-18 22:13:00.685 INFO| --[ Do Trace 0: {22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}: Microsoft-Windows-Kernel-Process
2024-08-18 22:13:00.685 INFO| ---[ Start tracing...
2024-08-18 22:13:00.686 INFO| ---[ All threads created
2024-08-18 22:13:00.686 INFO| --( Input: Kernel Reader
2024-08-18 22:13:00.686 INFO| --[ Start Thread 0
2024-08-18 22:13:00.687 INFO| --( Input: InjectedDll Reader
2024-08-18 22:13:00.691 INFO| Kernel Driver already loaded
2024-08-18 22:13:00.691 INFO| KernelReader: Waiting for client (Kernel Driver) to connect...
2024-08-18 22:13:00.692 INFO| Send IOCTL to kernel module: Enable: notepad
2024-08-18 22:13:00.692 INFO| KernelReader: connected
2024-08-18 22:13:00.693 INFO| Received from driver: 3: OK
2024-08-18 22:13:00.693 INFO| --( waiting for 3 threads...
KRN: 5676:process:10432:\Device\HarddiskVolume2\Windows\System32\notepad.exe:5676:\Device\HarddiskVolume2\Windows\explorer.exe:1
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\notepad.exe
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\ntdll.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\kernel32.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\KernelBase.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\gdi32.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\win32u.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\gdi32full.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\msvcp_win.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\ucrtbase.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\user32.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\combase.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\rpcrt4.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\SHCore.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\msvcrt.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.4355_none_60b8b9eb71f
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\imm32.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\RedEdr\RedEdrDll.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\vcruntime140d.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\ucrtbased.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\bcryptprimitives.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\advapi32.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\sechost.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\bcrypt.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\kernel.appcore.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\uxtheme.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\clbcatq.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\MrmCoreR.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\shell32.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\windows.storage.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\wldp.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\oleaut32.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\shlwapi.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\msctf.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\TextShaping.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\efswrt.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\mpr.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\WinTypes.dll
2024-08-18 22:13:02.689 INFO| DllReader: Client connected
2024-08-18 22:13:02.709 INFO| Observe CMD: 10432 \Device\HarddiskVolume2\Windows\System32\notepad.exe
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\twinapi.appcore.dll
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107B350:0:86016:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107B350:0:36864:0x1000:0x4
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\oleacc.dll
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44EF10;ImageSize:000002199A44F280;ProcessID:10432;ImageCheckSum:265248;TimeDateStamp:1643917504;DefaultBase:000002199A44FE10;ImageName:\Device\HarddiskVolume2\Windows\System32\notepad.exe;
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\TextInputFramework.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\CoreUIComponents.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\CoreMessaging.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\ws2_32.dll
KRN: 10432:image:10432;\Device\HarddiskVolume2\Windows\System32\ntmarta.dll
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107B4A0:0:32768:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107AFD0:0:20480:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107ACE0:0:118784:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107D340:0:4096:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107DF80:0:1048560:0x2000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107DF70:0:4096:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107CFB0:0:4096:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107E730:0x7fffffff:50:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107E7B0:0x7fffffff:48:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107AE00:0:12288:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107B6F0:0:4096:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107B410:0:12288:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107D510:0:4096:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107D000:0:4096:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107D480:0:8388608:0x2000:0x1
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107CA60:0:20480:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107CD70:0:8192:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107CDD0:0:8192:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107D0F0:0:4096:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107D128:0:1048576:0x2000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107D128:0:12288:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107D180:0:4096:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107C4B0:0:12288:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107CBC0:0:4096:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107BE90:0:8192:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107E320:0:12288:0x1000:0x4
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F910;ImageSize:000002199A44F500;ProcessID:10432;ImageCheckSum:2050764;TimeDateStamp:2317072115;DefaultBase:000002199A44F140;ImageName:\Device\HarddiskVolume2\Windows\System32\ntdll.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A450040;ImageSize:000002199A44FA50;ProcessID:10432;ImageCheckSum:783856;TimeDateStamp:2409472152;DefaultBase:000002199A44F410;ImageName:\Device\HarddiskVolume2\Windows\System32\kernel32.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F500;ImageSize:000002199A44F960;ProcessID:10432;ImageCheckSum:3204702;TimeDateStamp:380676353;DefaultBase:000002199A44F0A0;ImageName:\Device\HarddiskVolume2\Windows\System32\KernelBase.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F910;ImageSize:000002199A44F960;ProcessID:10432;ImageCheckSum:218727;TimeDateStamp:3634633287;DefaultBase:000002199A44F410;ImageName:\Device\HarddiskVolume2\Windows\System32\gdi32.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F0A0;ImageSize:000002199A44F910;ProcessID:10432;ImageCheckSum:144207;TimeDateStamp:3336608826;DefaultBase:000002199A44EEC0;ImageName:\Device\HarddiskVolume2\Windows\System32\win32u.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44ED30;ImageSize:000002199A44F410;ProcessID:10432;ImageCheckSum:1163626;TimeDateStamp:1604369872;DefaultBase:000002199A44F140;ImageName:\Device\HarddiskVolume2\Windows\System32\gdi32full.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F280;ImageSize:000002199A44FA50;ProcessID:10432;ImageCheckSum:659111;TimeDateStamp:958749903;DefaultBase:000002199A44F3C0;ImageName:\Device\HarddiskVolume2\Windows\System32\msvcp_win.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F6E0;ImageSize:000002199A44ED30;ProcessID:10432;ImageCheckSum:1076532;TimeDateStamp:2177850761;DefaultBase:000002199A44F640;ImageName:\Device\HarddiskVolume2\Windows\System32\ucrtbase.dll;
ProcessID:10432;ThreadID:3676;StartThread:3;ProviderName:Microsoft-Windows-Kernel-Process;ProcessID:10432;ThreadID:5020;StackBase:000002199A44F960;StackLimit:000002199A44EDD0;UserStackBase:000002199A44FF50;UserStackLimit:000002199A44F960;StartAddr:000002199A44F140;Win32StartAddr:000002199A44EEC0;TebBase:000002199A44EF10;SubProcessTag:0;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F6E0;ImageSize:000002199A44FC80;ProcessID:10432;ImageCheckSum:1745311;TimeDateStamp:4291603748;DefaultBase:000002199A44FE10;ImageName:\Device\HarddiskVolume2\Windows\System32\user32.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44FE10;ImageSize:000002199A44ED30;ProcessID:10432;ImageCheckSum:3511252;TimeDateStamp:3888075817;DefaultBase:000002199A44F640;ImageName:\Device\HarddiskVolume2\Windows\System32\combase.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44FF50;ImageSize:000002199A44FAF0;ProcessID:10432;ImageCheckSum:1214792;TimeDateStamp:1313216935;DefaultBase:000002199A44FE60;ImageName:\Device\HarddiskVolume2\Windows\System32\rpcrt4.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F3C0;ImageSize:000002199A44F460;ProcessID:10432;ImageCheckSum:731810;TimeDateStamp:2272255898;DefaultBase:000002199A44F0A0;ImageName:\Device\HarddiskVolume2\Windows\System32\SHCore.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F2D0;ImageSize:000002199A44FFA0;ProcessID:10432;ImageCheckSum:681663;TimeDateStamp:2616593924;DefaultBase:000002199A44F3C0;ImageName:\Device\HarddiskVolume2\Windows\System32\msvcrt.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F410;ImageSize:000002199A44EDD0;ProcessID:10432;ImageCheckSum:2715251;TimeDateStamp:4145438527;DefaultBase:000002199A44EDD0;ImageName:\Device\HarddiskVolume2\Windows\WinSxS\amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.19041.4355_none_60b8b9eb71f62e16\comctl32.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44FD20;ImageSize:000002199A44F960;ProcessID:10432;ImageCheckSum:244437;TimeDateStamp:3510600902;DefaultBase:000002199A44F140;ImageName:\Device\HarddiskVolume2\Windows\System32\imm32.dll;
ProcessID:10432;ThreadID:5020;StartThread:3;ProviderName:Microsoft-Windows-Kernel-Process;ProcessID:10432;ThreadID:9628;StackBase:000002199A44EF10;StackLimit:000002199A44FAF0;UserStackBase:000002199A44F730;UserStackLimit:000002199A44F410;StartAddr:000002199A44F730;Win32StartAddr:000002199A44FC80;TebBase:000002199A44ED80;SubProcessTag:0;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F730;ImageSize:000002199A44F140;ProcessID:10432;ImageCheckSum:0;TimeDateStamp:1723914219;DefaultBase:000002199A44FC80;ImageName:\Device\HarddiskVolume2\RedEdr\RedEdrDll.dll;DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107E8E0:0:4096:0x1000:0x4
DLL: pid:10432:AllocateVirtualMemory:FFFFFFFFFFFFFFFF:00000047B107E8D0:0:4096:0x1000:0x4

ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44EDD0;ImageSize:000002199A44F870;ProcessID:10432;ImageCheckSum:215677;TimeDateStamp:3390545094;DefaultBase:000002199A44FC80;ImageName:\Device\HarddiskVolume2\Windows\System32\vcruntime140d.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F410;ImageSize:000002199A44F460;ProcessID:10432;ImageCheckSum:2249853;TimeDateStamp:3642813796;DefaultBase:000002199A44EF10;ImageName:\Device\HarddiskVolume2\Windows\System32\ucrtbased.dll;
ProcessID:10432;ThreadID:3676;StartThread:3;ProviderName:Microsoft-Windows-Kernel-Process;ProcessID:10432;ThreadID:8208;StackBase:000002199A44FC80;StackLimit:000002199A44EEC0;UserStackBase:000002199A44FD70;UserStackLimit:000002199A44FF50;StartAddr:000002199A450040;Win32StartAddr:000002199A44EDD0;TebBase:000002199A44EEC0;SubProcessTag:0;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F2D0;ImageSize:000002199A44EEC0;ProcessID:10432;ImageCheckSum:552518;TimeDateStamp:4141345279;DefaultBase:000002199A44F1E0;ImageName:\Device\HarddiskVolume2\Windows\System32\bcryptprimitives.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F140;ImageSize:000002199A44EDD0;ProcessID:10432;ImageCheckSum:737504;TimeDateStamp:3424826873;DefaultBase:000002199A44FC80;ImageName:\Device\HarddiskVolume2\Windows\System32\advapi32.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F0A0;ImageSize:000002199A44F870;ProcessID:10432;ImageCheckSum:691703;TimeDateStamp:944590729;DefaultBase:000002199A44FFA0;ImageName:\Device\HarddiskVolume2\Windows\System32\sechost.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F3C0;ImageSize:000002199A44ED30;ProcessID:10432;ImageCheckSum:199345;TimeDateStamp:2535700803;DefaultBase:000002199A44EDD0;ImageName:\Device\HarddiskVolume2\Windows\System32\bcrypt.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F6E0;ImageSize:000002199A44F410;ProcessID:10432;ImageCheckSum:122143;TimeDateStamp:1990571354;DefaultBase:000002199A44EEC0;ImageName:\Device\HarddiskVolume2\Windows\System32\kernel.appcore.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F140;ImageSize:000002199A44EEC0;ProcessID:10432;ImageCheckSum:652983;TimeDateStamp:2037838987;DefaultBase:000002199A44EF60;ImageName:\Device\HarddiskVolume2\Windows\System32\uxtheme.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F870;ImageSize:000002199A44F000;ProcessID:10432;ImageCheckSum:736478;TimeDateStamp:97696835;DefaultBase:000002199A44FEB0;ImageName:\Device\HarddiskVolume2\Windows\System32\clbcatq.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F870;ImageSize:000002199A44F1E0;ProcessID:10432;ImageCheckSum:1076757;TimeDateStamp:2235875132;DefaultBase:000002199A44F6E0;ImageName:\Device\HarddiskVolume2\Windows\System32\MrmCoreR.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F910;ImageSize:000002199A44F140;ProcessID:10432;ImageCheckSum:7889512;TimeDateStamp:888945183;DefaultBase:000002199A44ED30;ImageName:\Device\HarddiskVolume2\Windows\System32\shell32.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F5A0;ImageSize:000002199A44ED80;ProcessID:10432;ImageCheckSum:8092454;TimeDateStamp:1976756177;DefaultBase:000002199A44F6E0;ImageName:\Device\HarddiskVolume2\Windows\System32\windows.storage.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F140;ImageSize:000002199A44F410;ProcessID:10432;ImageCheckSum:192391;TimeDateStamp:946832066;DefaultBase:000002199A44F550;ImageName:\Device\HarddiskVolume2\Windows\System32\wldp.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44FA50;ImageSize:000002199A44ED80;ProcessID:10432;ImageCheckSum:849765;TimeDateStamp:3559841777;DefaultBase:000002199A44F5A0;ImageName:\Device\HarddiskVolume2\Windows\System32\oleaut32.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F960;ImageSize:000002199A44FCD0;ProcessID:10432;ImageCheckSum:401062;TimeDateStamp:1783206983;DefaultBase:000002199A44FCD0;ImageName:\Device\HarddiskVolume2\Windows\System32\shlwapi.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F640;ImageSize:000002199A44F6E0;ProcessID:10432;ImageCheckSum:1142438;TimeDateStamp:445851090;DefaultBase:000002199A44FAF0;ImageName:\Device\HarddiskVolume2\Windows\System32\msctf.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44ED30;ImageSize:000002199A44F000;ProcessID:10432;ImageCheckSum:722774;TimeDateStamp:4284212041;DefaultBase:000002199A44F6E0;ImageName:\Device\HarddiskVolume2\Windows\System32\TextShaping.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F140;ImageSize:000002199A44FE60;ProcessID:10432;ImageCheckSum:914722;TimeDateStamp:483081012;DefaultBase:000002199A44FAF0;ImageName:\Device\HarddiskVolume2\Windows\System32\efswrt.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F140;ImageSize:000002199A44FB40;ProcessID:10432;ImageCheckSum:129330;TimeDateStamp:931921329;DefaultBase:000002199A44F000;ImageName:\Device\HarddiskVolume2\Windows\System32\mpr.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F550;ImageSize:000002199A44F410;ProcessID:10432;ImageCheckSum:1424514;TimeDateStamp:2716751106;DefaultBase:000002199A44ED30;ImageName:\Device\HarddiskVolume2\Windows\System32\WinTypes.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F870;ImageSize:000002199A44EEC0;ProcessID:10432;ImageCheckSum:2144556;TimeDateStamp:371345800;DefaultBase:000002199A44FA50;ImageName:\Device\HarddiskVolume2\Windows\System32\twinapi.appcore.dll;
ProcessID:10432;ThreadID:3676;StartThread:3;ProviderName:Microsoft-Windows-Kernel-Process;ProcessID:10432;ThreadID:3704;StackBase:000002199A44EF10;StackLimit:000002199A44F550;UserStackBase:000002199A44EF10;UserStackLimit:000002199A44F140;StartAddr:000002199A44FE60;Win32StartAddr:000002199A44F140;TebBase:000002199A44F6E0;SubProcessTag:0;
ProcessID:10432;ThreadID:3676;StartThread:3;ProviderName:Microsoft-Windows-Kernel-Process;ProcessID:10432;ThreadID:6012;StackBase:000002199A44F140;StackLimit:000002199A44F910;UserStackBase:000002199A44F6E0;UserStackLimit:000002199A44EF10;StartAddr:000002199A44EEC0;Win32StartAddr:000002199A44F6E0;TebBase:000002199A44FD70;SubProcessTag:0;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44F910;ImageSize:000002199A44F910;ProcessID:10432;ImageCheckSum:438444;TimeDateStamp:4130496952;DefaultBase:000002199A44FF50;ImageName:\Device\HarddiskVolume2\Windows\System32\oleacc.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44FB40;ImageSize:000002199A44F140;ProcessID:10432;ImageCheckSum:1049245;TimeDateStamp:1556083972;DefaultBase:000002199A44FB40;ImageName:\Device\HarddiskVolume2\Windows\System32\TextInputFramework.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44FB40;ImageSize:000002199A44FD70;ProcessID:10432;ImageCheckSum:3577987;TimeDateStamp:240915949;DefaultBase:000002199A44F000;ImageName:\Device\HarddiskVolume2\Windows\System32\CoreUIComponents.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44EF10;ImageSize:000002199A44F140;ProcessID:10432;ImageCheckSum:988081;TimeDateStamp:1777838427;DefaultBase:000002199A44EF10;ImageName:\Device\HarddiskVolume2\Windows\System32\CoreMessaging.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44FE60;ImageSize:000002199A44EF10;ProcessID:10432;ImageCheckSum:489137;TimeDateStamp:2047685052;DefaultBase:000002199A44FAF0;ImageName:\Device\HarddiskVolume2\Windows\System32\ws2_32.dll;
ProcessID:10432;ThreadID:3676;LoadImage:5;ProviderName:Microsoft-Windows-Kernel-Process;ImageBase:000002199A44FAF0;ImageSize:000002199A44EF10;ProcessID:10432;ImageCheckSum:197444;TimeDateStamp:4265087599;DefaultBase:000002199A44F000;ImageName:\Device\HarddiskVolume2\Windows\System32\ntmarta.dll;
```