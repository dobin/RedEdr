#pragma once

#define LOG_ERROR 0
#define LOG_WARNING 1
#define LOG_INFO 2
#define LOG_DEBUG 3

// LOG_A(LOG_ERROR, "FUCKME2 A: %s", "ARG1");
// LOG_W(LOG_ERROR, L"FUCKME2 W: %s", L"ARG2");

#if defined OUTPUT_STDOUT
#include <iostream>
#include <vector>
#include <string>

std::vector <std::string> GetLogs();
#endif

void LOG_W(int verbosity, const wchar_t* format, ...);
void LOG_A(int verbosity, const char* format, ...);

