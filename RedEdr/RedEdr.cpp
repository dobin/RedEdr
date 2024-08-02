#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>

#include "etwreader.h"
#include "kernelcom.h"
#include "cache.h"
#include "procinfo.h"

// Function to enable a privilege for the current process
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        std::cerr << "LookupPrivilegeValue error: " << GetLastError() << std::endl;
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        std::cerr << "AdjustTokenPrivileges error: " << GetLastError() << std::endl;
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "The token does not have the specified privilege." << std::endl;
        return FALSE;
    }

    return TRUE;
}

BOOL MakeDebug() {
    // Get a handle to the current process token
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return 1;
    }

    // Enable SeDebugPrivilege
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        std::cerr << "Failed to enable SeDebugPrivilege." << std::endl;
        CloseHandle(hToken);
        return 1;
    }

    printf("Debug: OK\n");
}


int main() {
    int a = 1;

    BOOL dbg = MakeDebug();
    if (!dbg) {
        printf("ERROR MakeDebug\n");
    }

    //printf("--> %d", GetProcessParentPid(4652));
    //return 1;
    //test();
    /*
    DWORD pid = 5208; // Replace with the PID you're interested in
    std::wstring cmdLine;
    if (GetProcessCommandLine(pid, cmdLine)) {
        std::wcout << L"Command Line: " << cmdLine << std::endl;
    }
    else {
        std::wcerr << L"Failed to get command line." << std::endl;
    }*/


    if (a == 1) {
        etwreader();
    }
    else if (a == 2) {
        kernelcom();
    }
    return 0;

    // Revert privilege
    //SetPrivilege(hToken, SE_DEBUG_NAME, FALSE);
    //CloseHandle(hToken);
}