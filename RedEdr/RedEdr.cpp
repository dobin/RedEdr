
#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <string.h>
#include <conio.h>   // For _kbhit() and _getch()

#include "cxxops.hpp"
#include "config.h"
#include "processcache.h"
#include "analyzer.h"
#include "webserver.h"
#include "kernelinterface.h"
#include "pplmanager.h"
#include "logging.h"
#include "manager.h"
#include "processinfo.h"

#include "../Shared/common.h"


BOOL keyboard_reader_flag = TRUE;


BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        LOG_A(LOG_WARNING, "\nRedEdr: Ctrl-c detected, performing shutdown");
        ManagerShutdown();
        keyboard_reader_flag = FALSE;
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
                g_ProcessCache.removeAll();
            }
        }
        Sleep(200);
    }
    return 0;
}


void CreateRequiredFiles() {
    LPCWSTR dir = L"c:\\rededr\\data";
    DWORD fileAttributes = GetFileAttributes(dir);
    if (fileAttributes == INVALID_FILE_ATTRIBUTES || !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        std::cout << "Directory does not exist. Creating it...\n";
        if (! CreateDirectory(dir, NULL)) {
            std::cerr << "Failed to create directory. Error: " << GetLastError() << "\n";
        }
    }
}


// https://github.com/s4dbrd/ETWReader
int main(int argc, char* argv[]) {
    cxxopts::Options options("RedEdr", "Maldev event recorder");
    options.add_options()
        // Input
        ("t,trace", "Process name to trace", cxxopts::value<std::string>())
        ("a,all", "Input: All", cxxopts::value<bool>())

        ("e,etw", "Input: Consume ETW Events", cxxopts::value<bool>()->default_value("false"))
        ("g,etwti", "Input: Consume ETW-TI Events", cxxopts::value<bool>()->default_value("false"))
        ("m,mplog", "Input: Consume Defender mplog file", cxxopts::value<bool>()->default_value("false"))
        ("k,kernel", "Input: Consume kernel callback events", cxxopts::value<bool>()->default_value("false"))
        ("i,inject", "Input: Consume DLL injection", cxxopts::value<bool>()->default_value("false"))
        ("c,dllcallstack", "Input: Enable DLL injection hook callstacks", cxxopts::value<bool>()->default_value("false"))

        // Output
        ("w,web", "Output: Web server", cxxopts::value<bool>()->default_value("false"))
        ("u,hide", "Output: Hide messages (performance. use with --web)", cxxopts::value<bool>()->default_value("false"))

        // Kernel
        ("1,krnload", "Kernel Module: Load", cxxopts::value<bool>()->default_value("false"))
        ("2,krnunload", "Kernel Module: Unload", cxxopts::value<bool>()->default_value("false"))
        
        // PPL
        ("4,pplstart", "PPL service: load", cxxopts::value<bool>()->default_value("false"))
        ("5,pplstop", "PPL service: stop", cxxopts::value<bool>()->default_value("false"))

        // Debug
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

	if (result["all"].as<bool>()) {
		g_config.do_etw = true;
		g_config.do_etwti = true;
		g_config.do_kernelcallback = true;
		g_config.do_dllinjection = true;
        g_config.do_dllinjection_ucallstack = true;
	} else if (!g_config.do_etw && !g_config.do_mplog && !g_config.do_kernelcallback 
        && !g_config.do_dllinjection && !g_config.do_etwti && !g_config.debug_dllreader) {
        printf("Choose at least one of --etw --etwti --kernel --inject --etwti (--dllreader for testing)");
        return 1;
    }

    CreateRequiredFiles();
    InitProcessInfo();

    // All threads of all *Reader subsystems
    std::vector<HANDLE> threads;
    LOG_A(LOG_INFO, "--( RedEdr 0.2");
    LOG_A(LOG_INFO, "--( Tracing process name %ls and its children", g_config.targetExeName);

    // SeDebug
    BOOL dbg = PermissionMakeMeDebug();
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
    ManagerStart(threads);

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