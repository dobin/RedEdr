# RedEdr

--> NOT RELEASE READY DO NOT USE <--

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

After compiling, you should have: 
* C:\RedEdr\RedEdr.exe: The userspace component
* C:\RedEdr\RedEdrDriver\*: The kernel module
* C:\RedEdr\RedEdrDll.dll: The injectable DLL (amsi.dll)


To load the driver, use local admin shell: 
```
> .\load-kernel-driver.bat
```

Execute as admin obviously. 

If you want ETW Microsoft-Windows-Security-Auditing, start as SYSTEM. 


## Usage

RedEdr will trace all processes containing argument 1 in its process image name (exe path). And its children, recursively. 

There are two main modes: 
* With kernel module
* Without kernel module

I recommend to use it with kernel module. For a quick test, you can use RedEdr without. 


```
PS > .\RedEdr.exe cobaltstrike.exe
```

If you want just the events, without any log output:
```
PS > .\RedEdr.exe cobaltstrike.exe 2>$null
```


Without kernel module: 
```
PS > .\RedEdr.exe --no-kernel cobaltstrike.exe
```


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



# Todo

* ETW-TI
* Kernel ETW?
* Kernel minifilter?
* AMSI provider


# Based on

Based on MyDumbEdr
* GPLv3
* https://sensepost.com/blog/2024/sensecon-23-from-windows-drivers-to-an-almost-fully-working-edr/
* https://github.com/sensepost/mydumbedr
* patched https://github.com/dobin/mydumbedr
* which seems to use: https://github.com/CCob/SylantStrike/tree/master/SylantStrike

With KAPC injection from:
* https://github.com/0xOvid/RootkitDiaries/

