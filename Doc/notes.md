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


## Kernel Log ETW Provider

The kernel driver (`RedEdrDriver`) emits its log messages via a modern
TraceLogging ETW provider instead of `DbgPrintEx`. The legacy `LOG_A` call
sites are unchanged; only the sink changed.

| Property      | Value                                  |
|---------------|----------------------------------------|
| Provider name | `RedEdr-Kernel-Log`                    |
| Provider GUID | `07a19134-15d7-4601-b106-4b7a7aafc582` |
| Event name    | `Log`                                  |
| Field `Message`   | ANSI string (the formatted log line) |
| Field `Severity`  | UInt32 (`LOG_*` value from `common.h`) |

### Severity -> ETW level mapping

| `LOG_*`     | Value | ETW level                  |
|-------------|-------|----------------------------|
| `LOG_ERROR` | 0     | `WINEVENT_LEVEL_ERROR` (2) |
| `LOG_WARNING` | 1   | `WINEVENT_LEVEL_WARNING` (3) |
| `LOG_INFO`  | 2     | `WINEVENT_LEVEL_INFO` (4)  |
| `LOG_DEBUG` | 3     | `WINEVENT_LEVEL_VERBOSE` (5) |

### Capturing the events

Real-time capture with `logman`:

```
logman start RedEdrKrnLog -p {07a19134-15d7-4601-b106-4b7a7aafc582} 0 0 -rt
logman stop RedEdrKrnLog
```

Or with xperf / PerfView / WPA by adding the provider GUID.

### Consuming from userspace (krabs stub)

A future `RedEdr` userspace reader can attach to the provider alongside the
existing providers in `RedEdr/etwreader.cpp`:

```cpp
krabs::provider<> rededrKrnLog(L"{07a19134-15d7-4601-b106-4b7a7aafc582}");
rededrKrnLog.add_on_event_callback([](const EVENT_RECORD& record) {
    // Parse TraceLogging fields: Message (ansi string), Severity (uint32)
    // Forward to g_EventAggregator / log sink.
});
trace_user.enable(rededrKrnLog);
```


## PPL Service Log ETW Provider

The PPL service (`RedEdrPplService`) emits its log messages via a modern
TraceLogging ETW provider instead of writing to `C:\rededr\pplservice.log`.
The legacy `LOG_A` / `LOG_W` call sites are unchanged; only the sink changed.

| Property      | Value                                  |
|---------------|----------------------------------------|
| Provider name | `RedEdr-PplService-Log`                |
| Provider GUID | `098bd1da-fc3b-46c0-becb-28b679f4a1a2` |
| Event name    | `Log`                                  |
| Field `Message`   | ANSI string (the formatted log line) |
| Field `Severity`  | UInt32 (`LOG_*` value from `common.h`) |

The severity -> ETW level mapping is identical to the kernel provider above.

### Capturing the events

Real-time capture with `logman`:

```
logman start RedEdrPplLog -p {098bd1da-fc3b-46c0-becb-28b679f4a1a2} 0 0 -rt
logman stop RedEdrPplLog
```

### Consumption in RedEdr

`RedEdr/ppllogreader.cpp` consumes these events via a dedicated krabs
`user_trace` (`RedEdrPplLog`) and forwards each message into the agent log
store (`AddAgentLog`), prefixed with `[PPL] [SEV]`. The reader is started in
`ManagerStart` before the PPL service is launched, and stopped in
`ManagerShutdown` after the PPL producer is disabled. PPL log lines therefore
appear in `GetAgentLogs()` and the `/api/logs/agent` REST endpoint alongside
RedEdr's own logs and the kernel driver logs.

