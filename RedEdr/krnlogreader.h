#pragma once

#include <windows.h>
#include <vector>


//
// KrnLogReader: Consumes ETW events from the RedEdr kernel driver's
// "RedEdr-Kernel-Log" TraceLogging provider (GUID
// 07a19134-15d7-4601-b106-4b7a7aafc582) and forwards each log message into
// the agent log store (AddAgentLog) so it is printed and available via
// GetAgentLogs() / the /api/logs/agent REST endpoint.
//
// The reader must be started BEFORE the kernel driver is loaded/configured so
// that the driver's DriverEntry and IOCTL log messages are captured.
//

// Start the kernel-log ETW reader thread. Blocks until the trace session is
// fully initialized and ready to receive events. Returns TRUE on success.
BOOL KrnLogReaderInit(std::vector<HANDLE>& threads);

// Stop the kernel-log ETW reader thread and clean up.
void KrnLogReaderShutdown();
