#pragma once

BOOL PermissionSetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL PermissionMakeMeDebug();
void ManagerShutdown();
BOOL ManagerStart(std::vector<HANDLE> threads);
BOOL ManagerReload();