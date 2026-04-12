# Notes

## Solutions

RedEdr: 
* ETW reader
* MPLOG reader
* pipe-server for RedEdrDll (`pipe\\RedEdrDllCom`)
* pipe-server for RedEdrDriver (`pipe\\RedEdrKrnCom`)
* pipe-client for RedEdrPplService (`pipe\\RedEdrPplService`)

RedEdrDriver:
* Kernel driver to capture kernel callbacks
* Will do KAPC injection
* connects to RedEdr `pipe\\RedEdrKrnCom` to transmit captured data
* Receives IOCTL from RedEdr to be instructed

RedEdrPplService: 
* to be loaded as PPL windows service
* To capture ETW-TI
* connects to RedEdr `pipe\\RedEdrDllCom` to transmit captured data
* provides `pipe\\RedEdrPplService` for RedEdr to connect to be instructed

RedEdrDll: 
* amsi.dll style, to be injected into target processes
* connects to RedEdr `pipe\\RedEdrDllCom` to transmit captured data
* will receive config from RedEdr first

RedEdrTester: 
* internal testing tool


## Notifications

Notify components about new config: 
* RedEdr: Automatic
* RedEdrDriver: send IOCTL
* RedEdrPplService: pipe
* RedEdrDll: pipe (automatic on new process creation))
