# RedEdr PPL Service

* Used to consume ETW-TI
* Will send it via pipe to main RedEdr
* Requires to be started as PPL service

References: 
* https://blog.tofile.dev/2020/12/16/elam.html


## Communication

RedEdrPplService provides a pipe to interact with it: 

```
#define PPL_SERVICE_PIPE_NAME L"\\\\.\\pipe\\RedEdrPplService"
```

Which is the `pipeServer` in `control.cpp`. It only receives
ASCII commands. Like: 
* `start:<processname>`: Observes <processname>
* `stop`: Indicate RedEdr.exe is being shutdown - disconnect `PPL_DATA_PIPE_NAME`
* `shutdown`: Shutdown the service (so the exe can be updated)

If RedEdr connects to this pipe, RedEdrPplService will 
automatically attempt to connect back to RedEdr's pipe: 

```
#define PPL_DATA_PIPE_NAME L"\\\\.\\pipe\\RedEdrPplData"
```

It will only send the matching events to this pipe. 


