#pragma once

BOOL IsRunningAsSystem();
BOOL PermissionMakeMeDebug();
BOOL IsServiceRunning(LPCWSTR driverName);
BOOL DoesServiceExist(LPCWSTR serviceName);
