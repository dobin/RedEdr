#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <tchar.h>
#include <cwchar>
#include <cstdlib>
#include <string.h>

#include "cxxops.hpp"
#include "config.h"
#include "dllinjector.h"
#include "etwreader.h"
#include "logreader.h"
#include "kernelreader.h"
#include "processcache.h"
#include "analyzer.h"
#include "webserver.h"
#include "processinfo.h"
#include "dllreader.h"
#include "kernelinterface.h"
#include "pplmanager.h"
#include "logging.h"


// Function to enable a privilege for the current process
BOOL PermissionSetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        LOG_A(LOG_ERROR, "LookupPrivilegeValue error: %d", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        LOG_A(LOG_ERROR, "AdjustTokenPrivileges error: %d", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        LOG_A(LOG_ERROR, "The token does not have the specified privilege.");
        return FALSE;
    }

    return TRUE;
}


BOOL PermissionMakeMeDebug() {
    // Get a handle to the current process token
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        LOG_A(LOG_ERROR, "OpenProcessToken failed: %d", GetLastError());
        return FALSE;
    }

    // Enable SeDebugPrivilege
    if (!PermissionSetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        LOG_A(LOG_ERROR, "Failed to enable SeDebugPrivilege.");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);

    LOG_A(LOG_INFO, "--[ Enable SE_DEBUG: OK");
    return TRUE;
}


BOOL ManagerStart(std::vector<HANDLE> threads) {
    // Do kernel module stuff first, as it can fail hard
    // we can then just bail out without tearing down the other threads
    if (g_config.do_kernelcallback || g_config.do_dllinjection) {
        if (IsServiceRunning(g_config.driverName)) {
            LOG_A(LOG_INFO, "Kernel: RedEdr Driver already loaded");
        }
        else {
            LOG_A(LOG_INFO, "RedEdr: Load Kernel Driver");
            if (!LoadKernelDriver()) {
                LOG_A(LOG_ERROR, "RedEdr: Could not load driver");
                return FALSE;
            }
        }

        // Start the kernel server first
        // The kernel module will connect to it
        LOG_A(LOG_INFO, "RedEdr: Start kernel reader  thread");
        KernelReaderInit(threads);

        // Enable it
        LOG_A(LOG_INFO, "RedEdr: Tell Kernel to start collecting telemetry of: \"%ls\"", g_config.targetExeName);
        const wchar_t* target = g_config.targetExeName;
        if (!EnableKernelDriver(1, (wchar_t*)target)) {
            LOG_A(LOG_ERROR, "RedEdr: Could not communicate with kernel driver, aborting.");
            return FALSE;
        }
    }
    if (g_config.do_etw) {
        LOG_A(LOG_INFO, "RedEdr: Start ETW reader thread");
        InitializeEtwReader(threads);
    }
    if (g_config.do_mplog) {
        LOG_A(LOG_INFO, "RedEdr: Start MPLOG Reader");
        InitializeLogReader(threads);
    }
    if (g_config.do_dllinjection || g_config.debug_dllreader || g_config.do_etwti) {
        LOG_A(LOG_INFO, "RedEdr: Start InjectedDll reader thread");
        DllReaderInit(threads);
    }
    if (g_config.do_etwti) {
        LOG_A(LOG_INFO, "RedEdr: Start ETW-TI reader");
        Sleep(500);
        wchar_t* target = (wchar_t*)g_config.targetExeName;
        InitPplService();
        EnablePplProducer(TRUE, target);
    }

    return TRUE;
}


void ManagerShutdown() {
    if (g_config.do_mplog) {
        LOG_A(LOG_INFO, "RedEdr: Stop log reader");
        LogReaderStopAll();
    }

    // Lets shut down ETW stuff first, its more important
    // ETW-TI
    if (g_config.do_etwti) {
        LOG_A(LOG_INFO, "RedEdr: Stop ETWTI reader");
        EnablePplProducer(FALSE, NULL);
    }
    // ETW
    if (g_config.do_etw) {
        LOG_A(LOG_INFO, "RedEdr: Stop ETW readers");
        EtwReaderStopAll();
    }

    // Make kernel module stop emitting events
    //    Disconnects KernelPipe client
    if (g_config.do_kernelcallback || g_config.do_dllinjection) {
        LOG_A(LOG_INFO, "RedEdr: Disable kernel driver");
        const wchar_t* target = L"";
        EnableKernelDriver(0, (wchar_t*)target);
    }

    // The following may crash?
    // Shutdown kernel reader
    if (g_config.do_kernelcallback) {
        LOG_A(LOG_INFO, "RedEdr: Stop kernel reader");
        KernelReaderShutdown();
    }
    // Shutdown dll reader
    if (g_config.do_dllinjection || g_config.do_etwti) {
        LOG_A(LOG_INFO, "RedEdr: Stop DLL reader");
        DllReaderShutdown();
    }

    // Special case
    if (g_config.debug_dllreader) {
        LOG_A(LOG_INFO, "RedEdr: Stop DLL reader");
        DllReaderShutdown();
    }

    // Web server
    if (g_config.web_output) {
        LOG_A(LOG_INFO, "RedEdr: Stop web server");
        StopWebServer();
    }

    // Analyzer
    StopAnalyzer();
}
