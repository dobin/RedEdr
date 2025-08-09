#pragma once

#include "../Shared/common.h"

// LOG_A(LOG_ERROR, "FUCKME2 A: %s", "ARG1");
// LOG_W(LOG_ERROR, L"FUCKME2 W: %s", L"ARG2");

#if defined OUTPUT_STDOUT
#include <iostream>
#include <vector>
#include <string>

std::vector <std::string> GetAgentLogs();
#endif

#if defined OUTPUT_PPL
void CleanupFileLogging();
#endif

void LOG_W(int verbosity, const wchar_t* format, ...);
void LOG_A(int verbosity, const char* format, ...);

