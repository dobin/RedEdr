#pragma once

BOOL EnableKernelDriver(int enable, std::string target);
BOOL LoadKernelDriver();
BOOL UnloadKernelDriver();
BOOL IsServiceRunning(LPCWSTR driverName);

