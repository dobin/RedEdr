#pragma once

#include "../Shared/common.h"

BOOL ConfigureKernelDriver(int enable);
BOOL ElevateProcessProtection(DWORD processId, UCHAR signer, UCHAR type);
BOOL LoadKernelDriver();
BOOL UnloadKernelDriver();
BOOL IsServiceRunning(LPCWSTR driverName);
