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

### POST /api/execute/exec
Executes given file (binary, malware).

Request: Multipart form data with file upload
- **Form Fields**:
  - `file` - The executable file to analyze (required)
  - `path` - Custom path for file storage (optional, defaults to "C:\\RedEdr\\data\\")
  - `use_additional_etw` - Enable additional ETW collection ("true"/"false")
  - `fileargs` - Command line arguments for the executable (optional)

Response: `application/json`
- **Success**: `{"status": "ok", "pid": process_id}`
- **Virus Detected**: `{"status": "virus", "pid": process_id}`
- **Error Responses**:
  - `{ "status": "error", "message": "error_description"}`
  - `400` - Invalid request (missing file or filename)
  - `500` - Execution failed

### POST /api/execute/kill
Kills the last executed process.
- **Response**: `{"status": "ok"}` on success
- **Error Responses**:
  - `{ "status": "error", "message": "Failed to kill last execution" }`
  - `500` - Kill operation failed


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
Get the logging output of the agent itself (combines agent and PPL service logs).

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

### GET /api/logs/execution
Retrieves executor information.

Response: `application/json`
- Object with execution details

Response example: 
```json
{
    "pid": 0,
    "stderr": "Command line error",
    "stdout": "Output content"
}
```

### GET /api/logs/edr
Get the data of the EDR log reader plugin.

Response: `application/json`
- Object with EDR logs and version information

Response example:
```json
{
    "logs":"<Events>\n</Events>",
    "edr_version":"1.0",
    "plugin_version":"1.0"
}
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


## Configuration Requirements

- **Remote Execution**: The `/api/execute/exec` and `/api/execute/kill` endpoints are only available when `g_Config.enable_remote_exec` is enabled
- **File Paths**: Static files are served from `C:\RedEdr\` directory
- **Data Storage**: Event recordings are stored in `C:\RedEdr\Data\` directory

## Example Usage

### Set multiple trace targets
```bash
curl -X POST http://localhost:8080/api/trace/start \
  -H "Content-Type: application/json" \
  -d '{"trace": ["malware1.exe", "malware2.exe"]}'
```

### Upload and execute file for analysis
```bash
curl -X POST http://localhost:8080/api/execute/exec -F "file=@/path/to/malware.exe"
```

### Kill last execution
```bash
curl -X POST http://localhost:8080/api/execute/kill
```

### Acquire resource lock
```bash
curl -X POST http://localhost:8080/api/lock/acquire
```

### Get current events
```bash
curl http://localhost:8080/api/logs/rededr
```

### Get system statistics
```bash
curl http://localhost:8080/api/stats
```