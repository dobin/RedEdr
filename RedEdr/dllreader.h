#pragma once

#include <windows.h>
#include <vector>


bool DllReaderInit(std::vector<HANDLE>& threads);
void DllReaderShutdown();
