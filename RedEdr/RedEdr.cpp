#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <tchar.h>
#include <cwchar>  // For wcstol
#include <cstdlib> // For exit()
#include "loguru.hpp"
#include "cxxops.hpp"
#include <string.h>     // for strcpy_s, strcat_s

#include "config.h"
#include "dllinjector.h"
#include "etwreader.h"
#include "logreader.h"
#include "kernelreader.h"
#include "cache.h"
#include "procinfo.h"
#include "injecteddllreader.h"
#include "driverinterface.h"
#include "../Shared/common.h"


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
    const wchar_t* target = L"";

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
        ioctl_enable_kernel_module(0, (wchar_t*)target);

        EtwReaderStopAll();

        LOG_F(WARNING, "--! 1");
        fflush(stdout); // Show to user immediately
        InjectedDllReaderStopAll();
        LOG_F(WARNING, "--! 2");
        fflush(stdout); // Show to user immediately
        KernelReaderStopAll();
        LOG_F(WARNING, "--! 3");
        fflush(stdout); // Show to user immediately

        //Sleep(1000);
        return TRUE; // Indicate that we handled the signal
    default:
        return FALSE; // Let the next handler handle the signal
    }
}


wchar_t* ConvertCharToWchar2(const char *arg) {
    int len = MultiByteToWideChar(CP_ACP, 0, arg, -1, NULL, 0);
    wchar_t* wargv = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, arg, -1, wargv, len);
    return wargv;
}


// https://github.com/s4dbrd/ETWReader
int main(int argc, char* argv[]) {
    cxxopts::Options options("RedEdr", "Maldev event recorder");
    options.add_options()
        ("t,trace", "Process name to trace", cxxopts::value<std::string>())
        ("e,etw", "Input: Consume ETW Events", cxxopts::value<bool>()->default_value("false"))
        ("m,mplog", "Input: Consume Defender mplog file", cxxopts::value<bool>()->default_value("false"))
        ("k,kernel", "Input: Consume kernel callback events", cxxopts::value<bool>()->default_value("false"))
        ("i,inject", "Input: Consume DLL injection", cxxopts::value<bool>()->default_value("false"))

        ("1,krnload", "Kernel Module: Load", cxxopts::value<bool>()->default_value("false"))
        ("2,krnreload", "Kernel Module: ReLoad", cxxopts::value<bool>()->default_value("false"))
        ("3,krnunload", "Kernel Module: Unload", cxxopts::value<bool>()->default_value("false"))

        ("d,debug", "Enable debugging", cxxopts::value<bool>()->default_value("false"))
        ("h,help", "Print usage")
        ;
    options.allow_unrecognised_options();
    auto result = options.parse(argc, argv);

    if (result.count("help") || result.unmatched().size() > 0) {
        printf("HMMM\n");
        std::cout << options.help() << std::endl;
        exit(0);
    }

    if (result.count("krnload")) {
        LoadDriver();
        exit(0);
    } else if (result.count("krnreload")) {
        if (CheckDriverStatus()) {
            UnloadDriver();
            LoadDriver();
        }
        else {
            LoadDriver();
        }
        exit(0);
    } else if (result.count("krnunload")) {
        UnloadDriver();
        exit(0);
    }

    if (result.count("trace")) {
        std::string s = result["trace"].as<std::string>();
        wchar_t* ss = ConvertCharToWchar2(s.c_str());
        g_config.targetExeName = ss;
    }
    else {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    g_config.do_etw = result["etw"].as<bool>();
    g_config.do_mplog = result["mplog"].as<bool>();
    g_config.do_kernelcallback = result["kernel"].as<bool>();
    g_config.do_dllinjection = result["inject"].as<bool>();

    if (!g_config.do_etw && !g_config.do_mplog && !g_config.do_kernelcallback && !g_config.do_dllinjection) {
        printf("Choose at least one of --etw --mplog --kernel --inject");
        return 1;
    }

    // All threads of all *Reader subsystems
    std::vector<HANDLE> threads;
    LOG_F(INFO, "--( RedEdr 0.2", g_config.targetExeName);
    LOG_F(INFO, "--( Tracing process name %ls and its children", g_config.targetExeName);

    // SeDebug
    BOOL dbg = makeMeSeDebug();
    if (!dbg) {
        LOG_F(ERROR, "--( ERROR MakeMeSeDebug: Did you start with local admin or SYSTEM?");
    }

    // Ctrl+C
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        LOG_F(ERROR, "--( Failed to set control handler");
        return 1;
    }

    // Functionality
    if (g_config.do_etw) {
        LOG_F(INFO, "--( Input: ETW Reader");
        InitializeEtwReader(threads);
    }
    if (g_config.do_mplog) {
        LOG_F(INFO, "--( Input: MPLOG Reader");
        InitializeLogReader(threads);
    }
    if (g_config.do_kernelcallback) {
        LOG_F(INFO, "--( Input: Kernel Reader");
        InitializeKernelReader(threads);
    }
    if (g_config.do_dllinjection) {
        LOG_F(INFO, "--( Input: InjectedDll Reader");
        InitializeInjectedDllReader(threads);
    }
    if (g_config.do_kernelcallback || g_config.do_dllinjection) {
        // load kernel module
        if (CheckDriverStatus()) {
            LOG_F(INFO, "Kernel Driver already loaded");
        } else {
            LOG_F(INFO, "Load Kernel Driver");
            if (!LoadDriver()) {
                LOG_F(ERROR, "Could not load driver");
            }
        }

        //Sleep(1000); // the thread with the server is not yet started...
        const wchar_t* target = g_config.targetExeName;
        ioctl_enable_kernel_module(1, (wchar_t*)target);
    }

    LOG_F(INFO, "--( waiting for %d threads...", threads.size());

    // Wait for all threads to complete
    // NOTE Stops after ctrl-c handler is executed?
    // etw: ControlTrace EVENT_TRACE_CONTROL_STOP all, which makes the threads return
    // logreader: threads will persist, but WaitForMultipleObject() will still return
    DWORD res = WaitForMultipleObjects(threads.size(), threads.data(), TRUE, INFINITE);
    if (res == WAIT_FAILED) {
        LOG_F(INFO, "--( Wait failed");
    }
    // No code here as it will not be executed?

    return 0;
}