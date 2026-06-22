#pragma once

#include <vector>
#include <string>

#include "../Shared/common.h"
void LOG_W(int verbosity, const wchar_t* format, ...);
void LOG_A(int verbosity, const char* format, ...);

// Append a pre-formatted log line to the agent log store (error_messages)
// with the same timestamped formatting as LOG_A. Used by external log
// sources (e.g. the kernel-log ETW reader) to surface their messages in
// GetAgentLogs() / the /api/logs/agent REST endpoint.
void AddAgentLog(const std::string& message);

std::vector <std::string> GetAgentLogs();

