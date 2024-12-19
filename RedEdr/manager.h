#pragma once

#include <stdio.h>
#include <windows.h>
#include <vector>

BOOL PermissionSetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
BOOL PermissionMakeMeDebug();
void ManagerShutdown();
BOOL ManagerStart(std::vector<HANDLE> threads);
BOOL ManagerReload();