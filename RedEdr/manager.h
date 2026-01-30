#pragma once

#include <windows.h>
#include <vector>
#include <string>

void ManagerShutdown();
BOOL ManagerStart(std::vector<HANDLE>& threads);
BOOL ManagerApplyNewTargets(std::vector<std::string> traceNames);