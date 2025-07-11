#pragma once

#include <windows.h>
#include <vector>

// PplReader: Consumes events from PPL service (ETW-TI data)

// Public Functions
bool PplReaderInit(std::vector<HANDLE>& threads);
void PplReaderShutdown();
