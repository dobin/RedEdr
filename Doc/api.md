# RedEdr HTTP API Documentation

RedEdr provides a REST API through an embedded HTTP server for interacting with the EDR system. The web server listens on a configurable port and provides both a web UI and programmatic API access.

## Data definition

- **Events**: a list of dict's


## API Endpoints

### POST /api/trace

Sets the process name to be observed.

Request: `application/json`
- `{"trace": "executable_name"}`

Response: `application/json`
- **Response**: `{"result": "ok"}` on success
- **Error Responses**:
  - `400` - Invalid JSON or missing 'trace' key

### GET /api/start

Starts the monitoring.

Response `application/json`:
- `{"status": "ok"}`


### POST /api/exec

Executes given file (binary, malware).

Request: Multipart form data with file upload
- **Form Field**: `file` - The executable file to analyze

Response: `application/json`
- `{"status": "ok"}`
- **Error Responses**:
  - `{ "status": "error", "message": "error reasoning>"}`
  - `400` - Invalid request (missing file or filename)
  - `500` - Execution failed


### GET /api/stop

Stops the monitoring.

Response `application/json`:
- **Response**: `{"status": "ok"}`


### GET /api/logs/rededr

Retrieves all captured events from the current session.
Events are things recorded by RedEdr, including ETW events, or DLL hooking events. 

Response: `application/json`
- `[ { ... }, { ... } ]`

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
    }, 
]
```


### GET /api/logs/agent

Get the logging output of the agent itself.

Response: `application/json`
- `[ "", "", "", ... ]`

Response example:
```json
[ 
    "RedEdr 0.4",
    "Config: tracing otepad",
    "Permissions: Enabled PRIVILEGED & DEBUG",
]
```

### GET /api/logs/execution

Retrieves executor information.

Response: `application/json`
- `{ "pid": 0, "stderr": "", "stdout": "" }`


Response example: 
```json
{
    "pid": 123,
    "stderr": "Command line error",
    "stdout": ""
}
```


### GET /api/logs/edr

Get the data of the EDR log reader plugin.

Response: `application/json`
- `{ "logs": "", "edr_version": "", "plugin_version": "" }`

Response example:
```json
{
    "logs":"<Events>\n</Events>",
    "edr_version":"1.0",
    "plugin_version":"1.0",
}
```


## UI Endpoints

### GET /api/recordings

Lists all available event recording files.
- **Response**: JSON array of recording filenames (*.events.json files)
- **Content-Type**: `application/json; charset=UTF-8`
- **Example Response**: `["recording1.events.json", "recording2.events.json"]`


### GET /api/recordings/:id
Retrieves a specific recording file by ID.
- **Parameters**: 
  - `id` (path parameter) - The recording filename
- **Response**: JSON content of the specified recording file
- **Content-Type**: `application/json`
- **Error Responses**:
  - `400` - Invalid ID (contains path traversal characters)
  - `404` - File not found

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

### GET /api/trace
Gets the current trace target executable name.
- **Response**: JSON object with current trace target
- **Content-Type**: `application/json`
- **Response Format**: `{"trace": "target_executable_name"}`


### GET /api/reset
Resets all captured events and system state.
- **Response**: Clears all current data
- **Side Effect**: All events and state are reset


### GET /api/save
Saves current events to a file.
- **Response**: Triggers save operation
- **Side Effect**: Events are saved to disk


## Error Handling

All API endpoints include comprehensive error handling:
- Malformed requests return appropriate HTTP status codes
- Internal server errors return `500` status with error details
- File not found errors return `404` status
- Invalid parameters return `400` status

## Security Considerations

- Path traversal protection on file access endpoints
- Remote execution capability can be disabled via configuration
- Input validation on all user-provided data
- Error messages don't expose sensitive system information


## Example Usage

### Set trace target
```bash
curl -X POST http://localhost:8080/api/trace \
  -H "Content-Type: application/json" \
  -d '{"trace": "malware.exe"}'
```

### Upload and execute file for analysis
```bash
curl -X POST http://localhost:8080/api/exec \
  -F "file=@/path/to/malware.exe"
```

### Get current events
```bash
curl http://localhost:8080/api/events
```