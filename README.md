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

## Permissions

Local admin:
* Microsoft-Windows-Kernel-Process

SYSTEM:
* Microsoft-Windows-Security-Auditing


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
* provides a pipe as server (send data to RedEdr client)

MyDumbEDRDLL: 
* amsi.dll style, to be injected into target processes
* use a pipe as client (send data to RedEdr server)

RedEdrTester: 
* internal testing


# Todo

* ETW-TI
* AMSI ntdll.dll hooking userspace
* AMSI ntdll.dll hooking kernelspace
* Kernel ETW?
* Kernel minifilter?


# Based on

MyDumbEdr
* GPLv3
* https://sensepost.com/blog/2024/sensecon-23-from-windows-drivers-to-an-almost-fully-working-edr/
* https://github.com/sensepost/mydumbedr
* https://github.com/dobin/mydumbedr

