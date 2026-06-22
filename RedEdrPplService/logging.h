#pragma once

#include <windows.h>
#include <TraceLoggingProvider.h>

#include "../Shared/common.h"


//
// RedEdr PPL Service Log ETW Provider (TraceLogging)
//
// Modern ETW replacement for the legacy file-based logging (pplservice.log).
// The provider emits one event per log call with the following shape:
//
//   Provider name : "RedEdr-PplService-Log"
//   Provider GUID : 098bd1da-fc3b-46c0-becb-28b679f4a1a2
//   Event name    : "Log"
//   Fields        : Message (ANSI string), Severity (UInt32)
//   Level         : mapped from LOG_* severity (see logging.cpp)
//
// RedEdr.exe consumes these events via a krabs-based reader (ppllogreader)
// and surfaces them in GetAgentLogs() / the /api/logs/agent REST endpoint,
// alongside RedEdr's own logs and the kernel driver logs.
//

//
// Define the TraceLogging provider. The GUID is fixed and must never change
// after the first release, otherwise existing consumers break.
//
//   098bd1da-fc3b-46c0-becb-28b679f4a1a2
//
// The provider is *defined* (once) in logging.cpp via TRACELOGGING_DEFINE_PROVIDER.
// All other translation units get the extern declaration below.
TRACELOGGING_DECLARE_PROVIDER(g_RedEdrPplLogProvider);


// Register the ETW provider. Must be called once at service start, before any
// LOG_A / LOG_W call. Returns TRUE on success.
BOOL PplLogInit(void);

// Unregister the ETW provider. Must be called once at service shutdown, as the
// very last action (after all LOG_A / LOG_W calls have completed).
void PplLogUninit(void);


void LOG_W(int verbosity, const wchar_t* format, ...);
void LOG_A(int verbosity, const char* format, ...);