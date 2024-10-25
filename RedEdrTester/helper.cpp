#include <stdio.h>
#include <windows.h>
#include <cwchar>
#include <cstdlib>
#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <iostream>

#include <wchar.h>
#include <stdio.h>
#include <dbghelp.h>
#include <tlhelp32.h>



DWORD FindProcessIdByName(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, processName.c_str())) {
                processId = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return processId;
}
