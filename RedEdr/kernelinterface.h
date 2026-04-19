#pragma once

BOOL ConfigureKernelDriver(int enable);
BOOL LoadKernelDriver();
BOOL UnloadKernelDriver();
BOOL IsServiceRunning(LPCWSTR driverName);
