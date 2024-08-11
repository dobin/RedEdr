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
  * ObRegisterCallbacks

## Permissions

Local admin:
* Microsoft-Windows-Kernel-Process

SYSTEM:
* Microsoft-Windows-Security-Auditing


## Usage

RedEdr will trace all processes containing argument 1 in its process image name (exe path). And its children, recursively. 

```
PS > .\RedEdr.exe cobaltstrike.exe
```

If you want just the events, without any log output:
```
PS > .\RedEdr.exe cobaltstrike.exe 2>$null
```


# Todo

* ETW-TI
* AMSI ntdll.dll hooking
