#pragma once


int kernelcom();
void InitializeKernelReader(std::vector<HANDLE>& threads);
void KernelReaderStopAll();
BOOL ConnectToServerPipe();