
#include <stdio.h>
#include <windows.h>
#include <iostream>
#include <string.h>
#include <conio.h>
#include <vector>

#include "logging.h"
#include "manager.h"
#include "cxxops.hpp"
#include "config.h"
#include "event_processor.h"
#include "event_aggregator.h"
#include "webserver.h"
#include "kernelinterface.h"
#include "pplmanager.h"
#include "dllinjector.h"
#include "utils.h"
#include "process_query.h"
#include "serviceutils.h"
#include "privileges.h"

#include "../Shared/common.h"


/* RedEdr.c: Main file
 *   Parse args
 *   Set flags in the Config object
 *   Init necessary things
 *   Start all threads (mostly through Manager)
 *   Wait for threads to exit
 */


BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        LOG_A(LOG_WARNING, "\nRedEdr: Ctrl-c detected, performing shutdown");
        ManagerShutdown();
        return TRUE; // Indicate that we handled the signal
    default:
        return FALSE; // Let the next handler handle the signal
    }
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


int main(int argc, char* argv[]) {
    cxxopts::Options options("RedEdr", "Maldev event recorder");
    options.add_options()
        // Input
        ("t,trace", "Process name to trace", cxxopts::value<std::string>())
        ("e,etw", "Input: Consume ETW Events", cxxopts::value<bool>()->default_value("false"))
        ("g,etwti", "Input: Consume ETW-TI Events", cxxopts::value<bool>()->default_value("false"))
        ("k,hook", "Input: Kernel and ntdll hooks", cxxopts::value<bool>()->default_value("false"))

        // Output
        ("w,web", "Output: Web server", cxxopts::value<bool>()->default_value("false"))
		("p,port", "Output: Web server port", cxxopts::value<int>()->default_value("8080"))
        ("u,hide", "Output: Hide messages (performance. use with --web)", cxxopts::value<bool>()->default_value("false"))

        // Kernel
        ("1,krnload", "Kernel Module: Load", cxxopts::value<bool>()->default_value("false"))
        ("2,krnunload", "Kernel Module: Unload", cxxopts::value<bool>()->default_value("false"))
        
        // PPL
        ("4,pplstart", "PPL service: load", cxxopts::value<bool>()->default_value("false"))
        ("5,pplstop", "PPL service: stop", cxxopts::value<bool>()->default_value("false"))

        // Debug
        ("l,dllreader", "Debug: DLL reader but no injection (for manual injection tests)", cxxopts::value<bool>()->default_value("false"))
        ("d,debug", "Debug: Enable debug output", cxxopts::value<bool>()->default_value("false"))
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
        // Instruct PPL service to exit itself (cant do it otherwise)
        // Note: we can replace the exe and start it again
        ShutdownPplService();
        exit(0);
    }

    if (result.count("trace")) {
        g_Config.targetExeName = result["trace"].as<std::string>();
    }
    else if (! result.count("test") && !result.count("replay")) {
        std::cout << options.help() << std::endl;
        exit(0);
    }

	int port = result["port"].as<int>();
    g_Config.do_etw = result["etw"].as<bool>();
    g_Config.do_etwti = result["etwti"].as<bool>();
	g_Config.do_hook = result["hook"].as<bool>();
    g_Config.debug_dllreader = result["dllreader"].as<bool>();
    g_Config.hide_full_output = result["hide"].as<bool>();
    g_Config.web_output = result["web"].as<bool>();
    //g_Config.do_dllinjection_ucallstack = result["dllcallstack"].as<bool>();

    /*
    if (!g_Config.do_etw && !g_Config.do_mplog && !g_Config.do_kernelcallback 
        && !g_Config.do_dllinjection && !g_Config.do_etwti && !g_Config.debug_dllreader) {
        printf("Choose at least one of --etw --etwti --kernel --inject --etwti (--dllreader for testing)");
        return 1;
    }*/

    CreateRequiredFiles();
    InitProcessQuery();
    g_EventProcessor.init(); // we also do it in constructor, but wont have g_Config

    // All threads of all *Reader subsystems
    std::vector<HANDLE> threads;
    LOG_A(LOG_INFO, "RedEdr %s", REDEDR_VERSION);
    LOG_A(LOG_INFO, "Config: tracing %s", g_Config.targetExeName.c_str());

    // SeDebug
    if (!PermissionMakeMeDebug()) {
        LOG_A(LOG_ERROR, "RedEdr: Permission error - Did you start with local admin?");
        //return 1;
    }
    if (!RunsAsSystem()) {
        LOG_A(LOG_WARNING, "RedEdr: Permission error - Not running as SYSTEM, some ETW data is not available");
    }

    // Ctrl+C
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        LOG_A(LOG_ERROR, "RedEdr: Failed to set control handler");
        return 1;
    }

    // Webserver
    if (g_Config.web_output) {
        InitializeWebServer(threads, port);
    }

    // Functionality
    ManagerStart(threads);
    InitializeEventProcessor(threads);

    // Wait for all threads to complete
    LOG_A(LOG_INFO, "RedEdr: All started, waiting for %llu threads to exit", threads.size());
    if (threads.empty()) {
        LOG_A(LOG_WARNING, "RedEdr: No threads to wait for");
        return 0;
    }
    
    // Log which threads we're waiting for
    //LOG_A(LOG_INFO, "RedEdr: Thread handles being tracked:");
    for (size_t i = 0; i < threads.size(); i++) {
        LOG_A(LOG_INFO, "Track Thread %zu (handle 0x%p)", i, threads[i]);
    }

    if (true) {
        // Wait for all threads to complete
        LOG_A(LOG_INFO, "RedEdr: All started, waiting for %llu threads to exit", threads.size());
        DWORD res = WaitForMultipleObjects((DWORD)threads.size(), threads.data(), TRUE, INFINITE);
        if (res == WAIT_FAILED) {
            LOG_A(LOG_INFO, "RedEdr: Wait failed");
        }
        LOG_A(LOG_INFO, "RedEdr: all %llu threads finished", threads.size());
    }
    else {
        // Wait with timeout to avoid hanging forever
        const DWORD SHUTDOWN_TIMEOUT_MS = 15000; // 15 seconds
        DWORD res = WaitForMultipleObjects((DWORD) threads.size(), threads.data(), TRUE, SHUTDOWN_TIMEOUT_MS);
    
        if (res == WAIT_TIMEOUT) {
            LOG_A(LOG_WARNING, "RedEdr: Thread shutdown timeout after %lu ms, some threads may not have terminated cleanly", SHUTDOWN_TIMEOUT_MS);
        
            // Log which threads are still running
            for (size_t i = 0; i < threads.size(); i++) {
                DWORD exitCode;
                if (GetExitCodeThread(threads[i], &exitCode)) {
                    if (exitCode == STILL_ACTIVE) {
                        LOG_A(LOG_WARNING, "RedEdr: Thread %zu (handle 0x%p) is still active", i, threads[i]);
                    } else {
                        LOG_A(LOG_INFO, "RedEdr: Thread %zu (handle 0x%p) has exited with code %lu", i, threads[i], exitCode);
                    }
                } else {
                    LOG_A(LOG_ERROR, "RedEdr: Failed to get exit code for thread %zu (handle 0x%p): %lu", i, threads[i], GetLastError());
                }
            }
        
            // Force termination as last resort
            LOG_A(LOG_WARNING, "RedEdr: Forcing termination of remaining active threads");
            for (size_t i = 0; i < threads.size(); i++) {
                DWORD exitCode;
                if (GetExitCodeThread(threads[i], &exitCode) && exitCode == STILL_ACTIVE) {
                    LOG_A(LOG_WARNING, "RedEdr: Forcibly terminating thread %zu (handle 0x%p)", i, threads[i]);
                    TerminateThread(threads[i], 1);
                }
            }
        }
        else if (res == WAIT_FAILED) {
            LOG_A(LOG_ERROR, "RedEdr: Wait failed with error: %lu", GetLastError());
            return 1;
        }
        else {
            LOG_A(LOG_INFO, "RedEdr: all %llu threads finished cleanly", threads.size());
        }
    }

    
    // Clean up thread handles
    for (HANDLE thread : threads) {
        CloseHandle(thread);
    }
    
    return 0;
}