#pragma once

#include <windows.h>
#include <vector>

void ManagerShutdown();
BOOL ManagerStart(std::vector<HANDLE>& threads);
BOOL ManagerApplyNewTargets();