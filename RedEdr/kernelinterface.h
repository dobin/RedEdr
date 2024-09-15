#pragma once

BOOL EnableKernelDriver(int enable, wchar_t* target);
BOOL LoadKernelDriver();
BOOL UnloadKernelDriver();
BOOL IsKernelDriverLoaded();

