#pragma once
#include <windows.h>

bool GetUserTokenForExecution(HANDLE& hTokenDup);
bool EnablePrivilege(HANDLE hToken, LPCWSTR privilege);
bool CheckPrivilege(HANDLE hToken, LPCWSTR privilege);
bool RunsAsSystem();
bool RunsAsAdmin();
