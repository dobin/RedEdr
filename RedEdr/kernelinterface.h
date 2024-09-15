#pragma once

BOOL ioctl_enable_kernel_module(int enable, wchar_t* target);
BOOL LoadKernelDriver();
BOOL UnloadKernelDriver();
BOOL DriverIsLoaded();

