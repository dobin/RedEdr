#pragma once

#include <vector>

bool KernelReaderInit(std::vector<HANDLE>& threads);
void KernelReaderShutdown();
