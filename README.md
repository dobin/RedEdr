# RedEdr

--> NOT RELEASE READY DO NOT USE <--

Display events from Windows to see the detection surface of your malware.

Same data as an EDR sees. 



## Implemented Providers

* ETW
  * Microsoft-Windows-Kernel-Process
  * Microsoft-Antimalware-Engine
  * Microsoft-Antimalware-RTP
  * Microsoft-Antimalware-AMFilter
  * Microsoft-Antimalware-Scan-Interface
  * Microsoft-Antimalware-Protection
  * Microsoft-Windows-Security-Auditing
    * needs SYSTEM
    * restrictions apply, see gpedit.msc -> Computer Configuration -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies - Local Group Policy object

* Kernel Callbacks
  * PsSetCreateProcessNotifyRoutine
  * PsSetCreateThreadNotifyRoutine
  * PsSetLoadImageNotifyRoutine
  * (ObRegisterCallbacks)

* AMSI ntdll.dll hooking from userspace (ETW based)
* AMSI ntdll.dll hooking from kernelspace (KAPC from LoadImage callback)


## Permissions

Local admin:
* ETW, especially Microsoft-Windows-Kernel-Process
* Driver loading

SYSTEM:
* ETW Microsoft-Windows-Security-Auditing


## Requirements

Use a VM.

To compile the kernel driver: 
* Install WDK (+SDK): https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

Change Windows boot options to enable self-signed kernel drivers:
```
bcdedit /set testsigning on
bcdedit -debug on
```

To load the driver, use local admin shell: 
```
> .\load-kernel-driver.bat
```


## Usage

RedEdr will trace all processes containing argument 1 in its process image name (exe path). And its children, recursively. 

```
PS > .\RedEdr.exe cobaltstrike.exe
```

If you want just the events, without any log output:
```
PS > .\RedEdr.exe cobaltstrike.exe 2>$null
```


## Solutions

RedEdr: 
* ETW reader
* MPLOG reader
* pipe-server for MyDumbEDRDLL
* pipe-client for MyDumbEDRDriver

MyDumbEDRDriver
* Kernel driver to capture kernel callbacks
* Will do KAPC injection
* provides a pipe as server (send data to RedEdr client)

MyDumbEDRDLL: 
* amsi.dll style, to be injected into target processes
* use a pipe as client (send data to RedEdr server)

RedEdrTester: 
* internal testing tool


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


