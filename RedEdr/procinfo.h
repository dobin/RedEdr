#pragma once

#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <winternl.h>

BOOL GetProcessCommandLine(DWORD dwPID, std::wstring& cmdLine);
BOOL GetProcessCommandLine2(DWORD dwPID, LPTSTR lpCmdLine, DWORD dwSize);
BOOL GetProcessWorkingDirectory2(DWORD dwPID, LPTSTR lpDirectory, DWORD dwSize);
