#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <tchar.h>

#include "loguru.hpp"
#include "config.h"
#include "etwreader.h"
#include "logreader.h"
#include "kernelcom.h"
#include "cache.h"
#include "procinfo.h"


// Function to enable a privilege for the current process
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        LOG_F(ERROR, "LookupPrivilegeValue error: %d", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        LOG_F(ERROR, "AdjustTokenPrivileges error: %d");
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        LOG_F(ERROR, "The token does not have the specified privilege.");
        return FALSE;
    }

    return TRUE;
}


BOOL makeMeSeDebug() {
    // Get a handle to the current process token
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        LOG_F(ERROR, "OpenProcessToken failed: %d", GetLastError());
        return FALSE;
    }

    // Enable SeDebugPrivilege
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        LOG_F(ERROR, "Failed to enable SeDebugPrivilege.");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);

    LOG_F(INFO, "--[ Enable SE_DEBUG: OK");
    return TRUE;
}

BOOL double_ctrlc = FALSE;
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        if (double_ctrlc) {
            LOG_F(INFO, "You already pressed ctrl-c. Be patient.");
            return TRUE;
        }
        double_ctrlc = TRUE;
        LOG_F(WARNING, "--! Ctrl-c detected, performing shutdown. Pls gife some time.");
        fflush(stdout); // Show to user immediately
        LogReaderStopAll();
        EtwReaderStopAll();
        KernelReaderStopAll();
        return TRUE; // Indicate that we handled the signal
    default:
        return FALSE; // Let the next handler handle the signal
    }
}


// https://github.com/s4dbrd/ETWReader
int wmain(int argc, wchar_t *argv[]) {
    if (argc != 2) {
        printf("Usage: rededr.exe <processname>");
        return 1;
    }

    std::vector<HANDLE> threads;

    BOOL do_etw = TRUE;
    BOOL do_mplog = FALSE;
    BOOL do_kernelcallback = FALSE;

    // Input
    g_config.targetExeName = argv[1];
    LOG_F(INFO, "--( Tracing process name %ls and its children", g_config.targetExeName);

    // SeDebug
    BOOL dbg = makeMeSeDebug();
    if (!dbg) {
        LOG_F(ERROR, "--( ERROR MakeMeSeDebug");
    }

    // Set up the console control handler to clean up on Ctrl+C
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        LOG_F(ERROR, "--( Failed to set control handler");
        return 1;
    }

    // Functionality
    if (do_etw) {
        InitializeEtwReader(threads);
    }
    if (do_mplog) {
        InitializeLogReader(threads);
    }
    if (do_kernelcallback) {
        // TODO
        InitializeKernelReader(threads);
    }

    LOG_F(INFO, "--( %d threads, waiting...", threads.size());

    // Wait for all threads to complete
    // NOTE Stops after ctrl-c handler is executed?
    // etw: ControlTrace EVENT_TRACE_CONTROL_STOP all, which makes the threads return
    // logreader: threads will persist, but WaitForMultipleObject() will still return
    DWORD result = WaitForMultipleObjects(threads.size(), threads.data(), TRUE, INFINITE);
    if (result == WAIT_FAILED) {
        LOG_F(INFO, "--( Wait failed");
    }

    return 0;
}