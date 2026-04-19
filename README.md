# RedEdr

Display events from Windows to see the detection surface of your malware. Same data as an ETW-based EDR sees (Defender, Elastic, Fibratus...). 

* Identify the telemetry your malware generates (detection surface)
* Verify your anti-EDR techniques work
* Debug and analyze your malware

It generates [JSON files](https://github.com/dobin/RedEdr/tree/master/Data)
collecting [the telemetry](https://github.com/dobin/RedEdr/blob/master/Doc/captured_events.md) 
of your RedTeaming tools. 

It is now part of Detonator, see [detonator.r00ted.ch](https://detonator.r00ted.ch). 


## Screenshots

Shellcode execution:
```c
	PVOID shellcodeAddr = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memcpy(shellcodeAddr, payload, payloadSize);
	VirtualProtect(shellcodeAddr, payloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection));
	HANDLE hThread = CreateThread(NULL, 0, shellcodeAddr, shellcodeAddr, 0, &threadId);
```

With ntdll.dll hooking:
![RedEdr Screenshot ntdll.dll hooking](https://raw.github.com/dobin/RedEdr/master/Doc/screenshot-web-rwx-dll.png)


ETW events:
![RedEdr Screenshot ETW](https://raw.github.com/dobin/RedEdr/master/Doc/screenshot-web-rwx-etw.png)


## Implemented Telemetry Consumers

* ETW
  * Microsoft-Windows-Kernel-Process
  * Microsoft-Windows-Kernel-Audit-API-Calls
  * Microsoft-Windows-Security-Auditing
  * Defender
    * Microsoft-Antimalware-Engine
    * Microsoft-Antimalware-RTP
    * Microsoft-Antimalware-AMFilter
    * Microsoft-Antimalware-Scan-Interface
    * Microsoft-Antimalware-Protection
  * ETW-TI (Threat Intelligence) with a PPL service via ELAM driver

* Kernel Callbacks
  * PsSetCreateProcessNotifyRoutine
  * PsSetCreateThreadNotifyRoutine
  * PsSetLoadImageNotifyRoutine
  * (ObRegisterCallbacks, not used atm)

* ntdll.dll hooking 

* Callstacks
  * On ntdll.dll hook invocation
  * On several ETW events
 
* process query
  * PEB
  * Loaded DLL's (and their regions)


## Installation

Use a dedicated VM for RedEdr. 

Extract release.zip into `C:\RedEdr`. **No other directories are supported.**

Whitelist `C:\RedEdr\RedEdr.exe` in your AV (Defender).

Start terminal as local admin.

Change into `C:\RedEdr` and run `.\RedEdr.exe`:
```
PS C:\rededr> .\RedEdr.exe
Maldev event recorder
Usage:
  RedEdr [OPTION...]
  -t, --trace arg     Process name to trace
  -e, --etw           Input: Consume ETW Events
  -g, --etwti         Input: Consume ETW-TI Events
  -m, --mplog         Input: Consume Defender mplog file
  -k, --kernel        Input: Consume kernel callback events
  -i, --inject        Input: Consume DLL injection
  -w, --web           Output: Web server
...
```

Try: `.\RedEdr.exe --etw --trace otepad`, and then start notepad 
(will be `notepad.exe` on Windows 10, `Notepad.exe` on Windows 11).
The log should be printed as stdout.


## Simple ETW Usage

RedEdr will trace all processes containing by process image name (exe path).

Capture ETW events and provide a web interface on [http://localhost:8081](http://localhost:8081):
```
PS > .\RedEdr.exe --etw --web --trace notepad.exe
```


## Advanced Usage

For ntdll.dll hooking and ETW-TI, we need to configure windows so it can
load our kernel module. 

Change Windows boot options to enable self-signed kernel drivers and reboot.

In admin cmd:
```
PS > bcdedit /set testsigning on

# required for win11 on proxmox even with secureboot disabled in bios
PS > bcdedit /set {bootmgr} testsigning on
PS > bcdedit /set {current} testsigning on
PS > bcdedit /set hypervisorlaunchtype off

PS > bcdedit -debug on
PS > shutdown /r /t 0
```

If you use Hyper-V, uncheck "Security -> Enable Secure Boot". 

If you use Proxmox, this works for me: 
* Reboot VM, press ESC a lot to go to BIOS menu
* Navigate to Device Manager > Secure Boot Configuration.
* Uncheck Attempt Secure Boot.
* Look for an option labeled Secure Boot Mode. Change it from Standard to Custom.
* Enter the Custom Secure Boot Options (or "Key Management").
* Select Delete all Secure Boot Variables (or "Clear Secure Boot Keys").


### ETW-TI

ETW-TI requires an ELAM driver to start `RedEdrPplService`, 
and therefore requires self signed kernel driver option.
Make a snapshot of your VM before doing this. Currently its 
not possible to remove the PPL service ever again. 

```
PS > .\RedEdr.exe --etw --etwti --trace notepad.exe
```

If you want ETW Microsoft-Windows-Security-Auditing, start as SYSTEM (`psexec -i -s cmd.exe`). 

See `gpedit.msc -> Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies - Local Group Policy object`
for settings to log.


### ntdll.dll hooking

KAPC DLL injection for ntdll.dll hooking. Thats what many older EDR's depend on. 
Also requires our own kernel module. 

```
PS > .\RedEdr.exe --hook --trace notepad.exe
```



## EDR Introspection (for Defender)

The following is useful to reverse engineer EDR's, and to verify your anti-EDR techniques
are targeted. It will observe Defender EDR. 

For more details, see Levi's blog at [My Hacker Blog](https://blog.levi.wiki/), 
and the [EDR-Introspection](https://github.com/cailllev/EDR-Introspection) project. 


### Microsoft-Antimalware-Engine ETW events

Argument: `--with-antimalwareengine`

Example: `.\RedEdr.exe --etw --trace putty --web --with-antimalwareengine`

This will collect `Microsoft-Antimalware-Engine` events related to the target process. 
See blog post [Defender Telemetry](https://blog.deeb.ch/posts/defender-telemetry/) for an overview of available events. 

For example the "Behavior Monitoring BmProcessContextStart", which indicates Defender will start behavior monitoring on the targeted process:
```
Behavior Monitoring BmProcessContextStart etw etw_event_id:0x6D etw_pid:0x1524 etw_process:MsMpEng.exe etw_provider_name:Microsoft-Antimalware-Engine etw_tid:0x37A8 etw_time:0x1DCC98C2B514B90 id:0x3 trace_id:0x29
imagepath:\Device\HarddiskVolume6\toolz\putty.exe pid:0x11F48 processcontextid:0x188F7789520
```


### MsMpEng.exe ETW events

Argument: `--with-defendertrace`

Example: `.\RedEdr.exe --etw --etwti --trace putty --web --with-defendertrace`

This will collect `msmpeng.exe` ETW events related to our target process. 
See blog post [Windows Telemetry](https://blog.deeb.ch/posts/windows-telemetry/) for an overview of available events. 

For example "Info" ETW event of "Microsoft-Windows-Kernel-Audit-API-Calls" accessing our target process:
```
Info etw etw_event_id:0x6 etw_pid:0x1524 etw_process:MsMpEng.exe etw_provider_name:Microsoft-Windows-Kernel-Audit-API-Calls etw_tid:0x21E0 etw_time:0x1DCC9BA7177FD80 id:0x1 trace_id:0x29
desiredaccess:0x1FFFFF returncode:0x0 targetprocessid:0x1524 targetthreatid:0x21E0
```


## Example Output

See `Data/` directory:
* [Data](https://github.com/dobin/RedEdr/tree/master/Data)


## Hacking

Arch:
```
      ┌─────┐  ┌────────┐ ┌─────────┐  ┌──────┐                            
      │ ETW │  │ ETW-TI │ │ Kernel  │  │ DLL  │                            
      └──┬──┘  └───┬────┘ └────┬────┘  └──┬───┘                            
         │         │           │          │                                
         └─────────┴─────────┬─┴──────────┘                                
                             │                                             
                             │                                             
                             ▼                                             
                     ┌────────────────┐                                    
                     │                │                                    
Event as JSON string │  Event         │                                    
                     │  Aggregator    │                                    
                     │                │               ┌──────────┐         
                     └───────┬────────┘               │ Process  │         
                             │                        └──────────┘         
                             │                             ▲               
                             ▼                             │query          
                     ┌────────────────┐                    │               
                     │                │         ┌──────────┴────┐          
Event as JSON in C++ │  Event         ├────────►│ Process Query │          
                     │  Processor     │         └─────────────┬─┘          
                     │                │                       │add         
                     └┬───────────────┘                       ▼            
                      │                                    ┌──────────────┐
                      │ ┌────────────────────────┐query    │              │
                      ├─┤Event Augment           ├────────►┤  Mem Static  │
                      │ └────────────────────────┘         │              │
                      │ ┌────────────────────────┐add      └──────────────┘
                      ├─┤Event Mem Tracker       ├──────┐                  
                      │ └────────────────────────┘      │  ┌──────────────┐
                      │ ┌────────────────────────┐query └─►│              │
                      ├─┤Event Detection         ├───┐     │ Mem Dynamic  │
                      │ └────────────────────────┘   └────►│              │
                      ▼ ┌────────────────────────┐         └──────────────┘
                      └─┤Event Storage & Output  │                         
                        └────────────────────────┘                         
```

IPC:
```
  RedEdr.exe                                                                                       
┌────────────┐                    ┌─────────────────┐                                             
│            │   KERNEL_PIPE      │                 │    KERNEL_PIPE: Events (wchar)              
│            │◄───────────────────┤   Kernel Module │                                             
│ Pipe Server│                    │                 │    IOCTL: Config (MY_DRIVER_DATA):          
│            ├───────────────────►│                 │             filename                        
│            │   IOCTL            └─────────────────┘             enable                          
│            │                                                                                    
│            │                                                                                    
│            │                                                                                    
│            │                                                                                    
│            │                    ┌─────────────────┐                                             
│            │   DLL_PIPE         │                 │  DLL_PIPE: 1: Config (wchar)   RedEdr -> DLL
│ Pipe Server│◄───────────────────┤  Injected DLL   │                 "callstack:1;"              
│            │                    │                 │                                             
│            │                    │                 │           >1: Events (wchar)   RedEdr <- DLL
│            │                    └─────────────────┘                                             
│            │                                                                                    
│            │                                                                                    
│            │                                                                                    
│            │                    ┌─────────────────┐                                             
│            │   PPL_PIPE         │                 │  DLL_PIPE: Events (wchar)                   
│ Pipe Server│◄───────────────────┤  ETW-TI Service │                                             
│            │                    │  PPL            │                                             
│            │   SERVICE_PIPE     │                 │  SERVICE_PIPE: Config (wchar)               
│ Pipe Client├───────────────────►│                 │                  "start:<process name>"     
│            │                    └─────────────────┘                                             
│            │                                                                                    
│            │                    ┌─────────────────┐                                             
│            │◄───────────────────┤                 │                                             
│            │                    │  ETW            │                                             
│            │                    │                 │                                             
│            │                    │                 │                                             
│            │                    └─────────────────┘                                             
│            │                                                                                    
│            │                                                                                    
└────────────┘                                                                                    
```


## Compiling 

Good luck.

Use VS2022. Compile as DEBUG.

To compile the kernel driver: 
* Install WDK (+SDK): https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

It should deploy everything into `C:\RedEdr\`.

On command line, use Visual Studio developer console. 

Everything:
```
repos\RedEdr>msbuild RedEdr.sln /p:Configuration=Debug /p:Platform=x64
```

RedEdr only:
```
repos\RedEdr>msbuild RedEdr.sln /p:Configuration=Debug /p:Platform=x64 /t:RedEdr
```


## Based on

Based on MyDumbEdr
* GPLv3
* https://sensepost.com/blog/2024/sensecon-23-from-windows-drivers-to-an-almost-fully-working-edr/
* https://github.com/sensepost/mydumbedr
* patched https://github.com/dobin/mydumbedr
* which seems to use: https://github.com/CCob/SylantStrike/tree/master/SylantStrike

With KAPC injection from:
* https://github.com/0xOvid/RootkitDiaries/
* No license

To run as PPL: 
* https://github.com/pathtofile/PPLRunner/
* No license


## Libraries used

* https://github.com/jarro2783/cxxopts, MIT
* https://github.com/yhirose/cpp-httplib, MIT
* https://github.com/nlohmann/json, MIT
