#pragma once

#include <vector>
#include <string>

#include "../Shared/common.h"
void LOG_W(int verbosity, const wchar_t* format, ...);
void LOG_A(int verbosity, const char* format, ...);

std::vector <std::string> GetAgentLogs();

