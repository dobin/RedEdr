#pragma once

BOOL PermissionMakeMePrivileged();
BOOL PermissionMakeMeDebug();
BOOL IsServiceRunning(LPCWSTR driverName);
BOOL DoesServiceExist(LPCWSTR serviceName);
