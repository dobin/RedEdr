# RedEdr

**Not ready to use yet :-( it will not work well**

Display events from Windows to see the detection surface of your malware.

Same data as an EDR sees. 

* Find the telemetry your malware generates
* Verify your anti-EDR techniques work
* Debug and analyze malware

RedEdr will observe one process, and identify malicious patterns. 
A normal EDR will observe all processes, and identify malicious processes. 

It generates JSON files like [this](https://github.com/dobin/RedEdr/tree/master/Data)
collecting all telemetry of some C2. 


## Implemented Telemetry Consumers

* ETW
  * Microsoft-Windows-Kernel-Process
  * Microsoft-Windows-Kernel-Audit-API-Calls
  * Microsoft-Windows-Security-Auditing
    * needs SYSTEM
    * restrictions apply, configure group policy
  * And defender
    * Microsoft-Antimalware-Engine
    * Microsoft-Antimalware-RTP
    * Microsoft-Antimalware-AMFilter
    * Microsoft-Antimalware-Scan-Interface
    * Microsoft-Antimalware-Protection
* ETW-TI (Threat Intelligence)

* Kernel Callbacks
  * PsSetCreateProcessNotifyRoutine
  * PsSetCreateThreadNotifyRoutine
  * PsSetLoadImageNotifyRoutine
  * (ObRegisterCallbacks, not used atm)

* AMSI ntdll.dll hooking 
  * from kernelspace (KAPC from LoadImage callback)
  * from userspace (ETW based, unreliable)

* Callstacks
  * On ntdll.dll hook invocation
 
* Loaded DLL's
  * In Userspace, on process create (ETW or Kernel)

* process information:
  * 

## Requirements

Use a VM. Tested on Win10. 

Change Windows boot options to enable self-signed kernel drivers and reboot:
```
bcdedit /set testsigning on
bcdedit -debug on
```

To compile the kernel driver: 
* Install WDK (+SDK): https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

After compiling solution (all "Debug"), you should have: 
* C:\RedEdr\RedEdr.exe: The userspace component
* C:\RedEdr\RedEdrDriver\*: The kernel module
* C:\RedEdr\RedEdrDll.dll: The injectable DLL (amsi.dll)

Everything should be in `C:\RedEdr`. No other directories are supported.

Start an local admin shell to execute `RedEdr.exe`. If you want ETW Microsoft-Windows-Security-Auditing, use SYSTEM (?). 


## Usage

RedEdr will trace all processes containing by process image name (exe path). And its children, recursively. 

There are two main modes: 
* With kernel module
* Without kernel module

I recommend to use it with kernel module. For a quick test, you can use RedEdr without. 
RedEdr only traces newly created processes, with the `--trace` argument in the image
name. After starting RedEdr, just start `notepad.exe`.


### Kernel module

Kernel module callbacks. And KAPC DLL injection: 
```
PS > .\RedEdr.exe --kernel --inject --trace notepad.exe
```

This requires self-signed kernel modules to load. 


### ETW 


Only ETW, no kernel module:
```
PS > .\RedEdr.exe --etw --trace notepad.exe
```

Start as SYSTEM to gain access to `Microsoft-Windows-Security-Auditing`. 
See `gpedit.msc -> Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies - Local Group Policy object`
for settings to log.


### ETWI-TI

ETW-TI requires an ELAM driver to start `RedEdrPplService`, 
and therefore requires self signed kernel driver option. 

Make a snapshot of your VM before doing this. Currently its 
not possible to remove the PPL service again. 

```
PS > .\RedEdr.exe --etwti --trace notepad.exe
```


### Real world usage

* Use `--callstacks` to print the callstack (currently only injected DLL hooks)


All input:
```
PS > .\RedEdr.exe --kernel --inject --etw --etwti --callstacks --trace notepad.exe
```

Provide as web on `http://localhost:8080`, and disable output logging for performance
(and improved stability):
```
PS > .\RedEdr.exe --kernel --inject --etw --etwti --callstacks --web --hide --trace notepad.exe
```


## Example Output

See `Data/` directory:
* [Data](https://github.com/dobin/RedEdr/tree/master/Data)


## Hacking

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

* https://github.com/dobin/RedEdr/blob/master/RedEdrDriver/kcallbacks.c
* https://github.com/dobin/RedEdr/blob/master/RedEdrDll/dllmain.cpp
* https://github.com/dobin/RedEdr/blob/master/RedEdr/etwreader.cpp
* https://github.com/dobin/RedEdr/blob/master/RedEdr/dllreader.cpp
* https://github.com/dobin/RedEdr/blob/master/RedEdr/kernelreader.cpp


## Todo

More consumers:
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
* No license

To run as PPL: 
* https://github.com/pathtofile/PPLRunner/
* No license

