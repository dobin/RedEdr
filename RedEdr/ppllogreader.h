#pragma once

#include <windows.h>
#include <vector>


//
// PplLogReader: Consumes ETW events from the RedEdr PPL service's
// "RedEdr-PplService-Log" TraceLogging provider (GUID
// 098bd1da-fc3b-46c0-becb-28b679f4a1a2) and forwards each log message into
// the agent log store (AddAgentLog) so it is printed and available via
// GetAgentLogs() / the /api/logs/agent REST endpoint.
//
// The reader must be started BEFORE the PPL service is started so that the
// service's startup log messages are captured.
//

// Start the PPL service log ETW reader thread. Blocks until the trace session
// is fully initialized and ready to receive events. Returns TRUE on success.
BOOL PplLogReaderInit(std::vector<HANDLE>& threads);

// Stop the PPL service log ETW reader thread and clean up.
void PplLogReaderShutdown();
