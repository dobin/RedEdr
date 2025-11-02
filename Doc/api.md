# RedEdr HTTP API Documentation

This document is AI generated but reviewed.

RedEdr provides a REST API through an embedded HTTP server for interacting with the EDR system. The web server listens on a configurable port and provides both a web UI and programmatic API access.

## Data definition

**Events** can be viewed as a dict (key value pair). It is mostly flat, but can contain arrays or further dicts: 
```

```


## HTTP UI

Provides a easy to use web interface for RedEdr on localhost.

### GET /
Serves the main web UI.
- **Response**: HTML content of the main interface

### GET /static/design.css
Serves the CSS stylesheet.
- **Response**: CSS content for styling

### GET /static/shared.js
Serves the JavaScript file.
- **Response**: JavaScript content for the web interface

### GET /api/stats
Returns system statistics and counters.
- **Response**: JSON object with event counts and statistics
- **Content-Type**: `application/json; charset=UTF-8`
- **Response Fields**:
  - `events_count` - Total number of events
  - `num_kernel` - Number of kernel events
  - `num_etw` - Number of ETW events
  - `num_etwti` - Number of ETW TI events
  - `num_dll` - Number of DLL events
  - `num_process_cache` - Number of cached processes

### GET /api/save
Saves current events to a file.
- **Response**: Triggers save operation
- **Side Effect**: Events are saved to disk


## Enable Tracing and Payload Execution

Used to define what RedEdr will look at, and provides an option
to also execute the malware. Primarily used by Detonator. 


### GET /api/trace/info
Gets the current trace target executable names.
- **Response**: JSON object with current trace targets
- **Content-Type**: `application/json`
- **Response Format**: `{"trace": ["target1", "target2"]}`

### POST /api/trace/start
Sets the process name(s) to be observed.

Request: `application/json`
- `{"trace": ["executable1", "executable2"]}` - Multiple targets

Response: `application/json`
- **Response**: `{"result": "ok"}` on success
- **Error Responses**:
  - `400` - Invalid JSON or missing arguments

### POST /api/trace/reset
Resets all captured events and system state.
- **Response**: Clears all current data
- **Side Effect**: All events and state are reset


## Retrieve Log Results

Actually retrieve the recorded logs of all involved components. 


### GET /api/logs/rededr

Retrieves all captured events from the current session.
Events are things recorded by RedEdr, including ETW events, or DLL hooking events.

Response: `application/json`
- Array of event objects

Response Example:
```json
[
    { 
        "date":"2025-07-20-10-36-24",
        "do_etw":false,
        "do_etwti":false,
        "do_hook":false,
        "do_hook_callstack": true,
        "func":"init",
        "target":"otepad",
        "trace_id":41,
        "type":"meta",
        "version":"0.4"
    }
]
```

### GET /api/logs/agent
Get the logging output of the agent itself (RedEdr and also RedEdrPplService).

Response: `application/json`
- Array of log strings

Response example:
```json
[ 
    "RedEdr 0.4",
    "Config: tracing otepad",
    "Permissions: Enabled PRIVILEGED & DEBUG"
]
```


## Lock Management

If RedEdr is used by multiple users, they can lock RedEdr for their
duration of use. If this is not being done, weird results will happen.

### POST /api/lock/acquire
Acquires a resource lock to prevent concurrent access.
- **Response**: `200 OK` if lock acquired successfully
- **Error Responses**:
  - `409 Conflict` - Resource is already in use
  - `{"status": "error", "message": "Resource is already in use"}`

### POST /api/lock/release
Releases the resource lock.
- **Response**: `200 OK` - Lock released

### GET /api/lock/status
Gets the current lock status.
- **Response**: JSON object with lock state
- **Response Format**: `{"in_use": true/false}`

