
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
#include <conio.h>   // For _kbhit() and _getch()

#include "cxxops.hpp"
#include "config.h"
#include "dllinjector.h"
#include "etwreader.h"
#include "logreader.h"
#include "kernelreader.h"
#include "cache.h"
#include "analyzer.h"
#include "webserver.h"
#include "procinfo.h"
#include "dllreader.h"
#include "kernelinterface.h"
#include "pplmanager.h"
#include "logging.h"

#include "../Shared/common.h"


BOOL keyboard_reader_flag = TRUE;

// Function to enable a privilege for the current process
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
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


BOOL makeMeSeDebug() {
    // Get a handle to the current process token
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        LOG_A(LOG_ERROR, "OpenProcessToken failed: %d", GetLastError());
        return FALSE;
    }

    // Enable SeDebugPrivilege
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        LOG_A(LOG_ERROR, "Failed to enable SeDebugPrivilege.");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);

    LOG_A(LOG_INFO, "--[ Enable SE_DEBUG: OK");
    return TRUE;
}


void shutdown_all() {
    if (g_config.do_mplog) {
        LOG_A(LOG_INFO, "RedEdr: Stop log reader");
        LogReaderStopAll();
    }

    // Lets shut down ETW stuff first, its more important
    // ETW-TI
    if (g_config.do_etwti) {
        LOG_A(LOG_INFO, "RedEdr: Stop ETWTI reader");
        EnablePplService(FALSE, NULL);
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

    // Keyboard reader
    keyboard_reader_flag = FALSE;

    // Analyzer
    StopAnalyzer();
}


BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        LOG_A(LOG_WARNING, "\nRedEdr: Ctrl-c detected, performing shutdown");
        shutdown_all();
        return TRUE; // Indicate that we handled the signal
    default:
        return FALSE; // Let the next handler handle the signal
    }
}


DWORD WINAPI KeyboardReaderThread(LPVOID param) {
    while (keyboard_reader_flag) {
        if (_kbhit()) {  // Check if a key was pressed
            char ch = _getch();  // Get the character
            if (ch == 'r') {
                LOG_A(LOG_WARNING, "Resetting data...");
                g_cache.removeAll();
            }
        }
        Sleep(200);
    }
    return 0;
}


// https://github.com/s4dbrd/ETWReader
int main(int argc, char* argv[]) {
    cxxopts::Options options("RedEdr", "Maldev event recorder");
    options.add_options()
        ("t,trace", "Process name to trace", cxxopts::value<std::string>())
        ("e,etw", "Input: Consume ETW Events", cxxopts::value<bool>()->default_value("false"))
        ("g,etwti", "Input: Consume ETW-TI Events", cxxopts::value<bool>()->default_value("false"))
        ("m,mplog", "Input: Consume Defender mplog file", cxxopts::value<bool>()->default_value("false"))
        ("k,kernel", "Input: Consume kernel callback events", cxxopts::value<bool>()->default_value("false"))
        ("i,inject", "Input: Consume DLL injection", cxxopts::value<bool>()->default_value("false"))
        ("c,dllcallstack", "Input: Enable DLL injection hook callstacks", cxxopts::value<bool>()->default_value("false"))
        ("w,web", "Output: Web server", cxxopts::value<bool>()->default_value("false"))
        ("u,hide", "Output: Hide messages (performance. use with --web)", cxxopts::value<bool>()->default_value("false"))

        ("1,krnload", "Kernel Module: Load", cxxopts::value<bool>()->default_value("false"))
        ("2,krnunload", "Kernel Module: Unload", cxxopts::value<bool>()->default_value("false"))
        
        ("4,pplstart", "PPL service: load", cxxopts::value<bool>()->default_value("false"))
        ("5,pplstop", "PPL service: stop", cxxopts::value<bool>()->default_value("false"))

        ("l,dllreader", "Debug: DLL reader but no injection (for manual injection tests)", cxxopts::value<bool>()->default_value("false"))
        ("d,debug", "Enable debugging", cxxopts::value<bool>()->default_value("false"))
        ("h,help", "Print usage")
        ;
    options.allow_unrecognised_options();
    auto result = options.parse(argc, argv);

    if (result.count("help") || result.unmatched().size() > 0) {
        printf("Unrecognized argument\n");
        std::cout << options.help() << std::endl;
        exit(0);
    }

    if (result.count("krnload")) {
        LoadKernelDriver();
        exit(0);
    } else if (result.count("krnunload")) {
        UnloadKernelDriver();
        exit(0);
    }
    else if (result.count("pplstart")) {
        InstallElamCertPpl();
        InstallPplService();
        exit(0);
    }
    else if (result.count("pplstop")) {
        // remove_ppl_service();  // Needs to be started as PPL to work

        // Instruct service to exit itself
        // We can replace the exe and start it again
        ShutdownPplService();
        exit(0);
    }

    if (result.count("trace")) {
        std::string s = result["trace"].as<std::string>();
        wchar_t* ss = ConvertCharToWchar(s.c_str());
        g_config.targetExeName = ss;
    }
    else {
        std::cout << options.help() << std::endl;
        exit(0);
    }

    g_config.do_etw = result["etw"].as<bool>();
    g_config.do_etwti = result["etwti"].as<bool>();
    g_config.do_mplog = result["mplog"].as<bool>();
    g_config.do_kernelcallback = result["kernel"].as<bool>();
    g_config.do_dllinjection = result["inject"].as<bool>();
    g_config.debug_dllreader = result["dllreader"].as<bool>();
    g_config.hide_full_output = result["hide"].as<bool>();
    g_config.web_output = result["web"].as<bool>();
    g_config.do_dllinjection_ucallstack = result["dllcallstack"].as<bool>();

    if (!g_config.do_etw && !g_config.do_mplog && !g_config.do_kernelcallback 
        && !g_config.do_dllinjection && !g_config.debug_dllreader && !g_config.do_etwti) {
        printf("Choose at least one of --etw --mplog --kernel --inject --dllreader --etwti");
        return 1;
    }

    // All threads of all *Reader subsystems
    std::vector<HANDLE> threads;
    LOG_A(LOG_INFO, "--( RedEdr 0.2");
    LOG_A(LOG_INFO, "--( Tracing process name %ls and its children", g_config.targetExeName);

    // SeDebug
    BOOL dbg = makeMeSeDebug();
    if (!dbg) {
        LOG_A(LOG_ERROR, "RedEdr: ERROR MakeMeSeDebug: Did you start with local admin or SYSTEM?");
    }

    // Ctrl+C
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        LOG_A(LOG_ERROR, "RedEdr: Failed to set control handler");
        return 1;
    }

    if (g_config.web_output) {
        InitializeWebServer(threads);
    }

    // Functionality
    
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
                return 1;
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
            return 1;
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
        //Sleep(1000);
        wchar_t* target = (wchar_t* )g_config.targetExeName;
        EnablePplService(TRUE, target);
    }

    // Keyboard reader
    HANDLE thread = CreateThread(NULL, 0, KeyboardReaderThread, NULL, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "Failed to create thread");
        return 1;
    }
    threads.push_back(thread);

    // Analyzer
    InitializeAnalyzer(threads);

    // Wait for all threads to complete
    LOG_A(LOG_INFO, "RedEdr: waiting for %llu threads...", threads.size());
    DWORD res = WaitForMultipleObjects((DWORD) threads.size(), threads.data(), TRUE, INFINITE);
    if (res == WAIT_FAILED) {
        LOG_A(LOG_INFO, "RedEdr: Wait failed");
    }
    LOG_A(LOG_INFO, "RedEdr: all %llu threads finished", threads.size());

    return 0;
}