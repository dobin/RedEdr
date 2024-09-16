# RedEdr PPL Service

* Used to consume ETW-TI
* Requires to be started as PPL
* As a service


References: 
* https://blog.tofile.dev/2020/12/16/elam.html
* 


## Startup

* main() -> service_entry() -> ServiceMain()
* ServiceMain(): Start Control (Pipe Server with commands, in `control.c`)
* ServiceMain(): Start Consumer (ETW-TI Consumer, in `consumer.c`)

* Control: 
  * As Thread
  * Enable, Disable ETW consumption and forwarding to RedEdr (via `consumer.c`)
  * Shutdown: Shutdown all modules and the service, putting it into STOPPED (can be started again from non-PPL)

* Consumer: 
  * Callback for ETW-TI
  * will block from ServiceMain() upon ProcessTrace()

* Emitter:
  * Pipe connection to RedEdr.exe
  * Connect/Disconnect on Control commands "start", "stop"


## Shutdown

* From: RedEdr.exe, via Control pipe, command "shutdown"
* Shutdown: Control (Pipe, and with it it's thread)
* Shutdown: ETW reader (ControlTrace, CloseTrace)
  * And with it ServiceMain()
