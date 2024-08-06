#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <tchar.h>

#include "config.h"
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


BOOL makeMeSeDebug() {
    // Get a handle to the current process token
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        std::cerr << "OpenProcessToken failed: " << GetLastError() << std::endl;
        return FALSE;
    }

    // Enable SeDebugPrivilege
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        std::cerr << "Failed to enable SeDebugPrivilege." << std::endl;
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);

    printf("--[ Enable SE_DEBUG: OK\n");
    return TRUE;
}


// https://github.com/s4dbrd/ETWReader
int wmain(int argc, wchar_t *argv[]) {
    if (argc != 2) {
        printf("Usage: rededr.exe <processname>");
        return 1;
    }

    BOOL do_etw = TRUE;
    BOOL do_mplog = TRUE;
    BOOL do_kernelcallback = FALSE;

    // Input
    g_config.targetExeName = argv[1];
    printf("--[ Tracing process name %ls and its children\n", g_config.targetExeName);

    // SeDebug
    BOOL dbg = makeMeSeDebug();
    if (!dbg) {
        printf("ERROR MakeMeSeDebug\n");
    }

    // Start
    if (do_etw) {
        // Creates threads in the background and a ctrl-c handler
        EtwReader();
    }
    if (do_mplog) {

    }
    if (do_kernelcallback) {
        // TODO
        kernelcom();
    }


    return 0;
}