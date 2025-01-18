
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

#include "../Shared/common.h"


/* RedEdr.c: Main file
 *   Parse args
 *   Set flags in the Config object
 *   Init necessary things
 *   Start all threads (mostly through Manager)
 *   Wait for threads to exit
 */


BOOL keyboard_reader_running = TRUE;


BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        LOG_A(LOG_WARNING, "\nRedEdr: Ctrl-c detected, performing shutdown");
        ManagerShutdown();
        keyboard_reader_running = FALSE;
        return TRUE; // Indicate that we handled the signal
    default:
        return FALSE; // Let the next handler handle the signal
    }
}


DWORD WINAPI KeyboardReaderThread(LPVOID param) {
    while (keyboard_reader_running) {
        if (_kbhit()) {  // Check if a key was pressed
            char ch = _getch();  // Get the character
            if (ch == 'r') {
                LOG_A(LOG_WARNING, "Resetting data...");
                ResetEverything();
            }
        }
        Sleep(200);
    }
    return 0;
}


BOOL InitKeyboardReader(std::vector<HANDLE>& threads) {
    HANDLE thread = CreateThread(NULL, 0, KeyboardReaderThread, NULL, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "Failed to create thread");
        return FALSE;
    }
    threads.push_back(thread);
    return TRUE;
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


// Pushes all events to the EventAggregator (like normal operation)
// Just have to make sure the process query aint happening
void ReplayEvents(std::string filename) {
    LOG_A(LOG_INFO, "Replaying file: %s", filename.c_str());
    FILE* recording_file = NULL;
    errno_t err = fopen_s(&recording_file, filename.c_str(), "r");
    if (err != 0 || !recording_file) {
        LOG_A(LOG_ERROR, "Could not open %s for reading", filename.c_str());
    }

	g_Config.replay_events = true;
    char buffer[DATA_BUFFER_SIZE];
    while (fgets(buffer, DATA_BUFFER_SIZE, recording_file)) {
        std::wstring bufferw = string2wstring(std::string(buffer));
        g_EventAggregator.do_output(bufferw);
    }
    fclose(recording_file);
}


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
        ("r,record", "Debug: Record all events to file", cxxopts::value<std::string>())
        ("p,replay", "Debug: Replay all events from file", cxxopts::value<std::string>())
        ("x,test", "Debug: start parts of RedEdr for testing", cxxopts::value<std::string>())
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
        // remove_ppl_service();  // Needs to be started as PPL to work

        // Instruct service to exit itself
        // We can replace the exe and start it again
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

    g_Config.do_etw = result["etw"].as<bool>();
    g_Config.do_etwti = result["etwti"].as<bool>();
    g_Config.do_mplog = result["mplog"].as<bool>();
    g_Config.do_kernelcallback = result["kernel"].as<bool>();
    g_Config.do_dllinjection = result["inject"].as<bool>();
    g_Config.debug_dllreader = result["dllreader"].as<bool>();
    g_Config.hide_full_output = result["hide"].as<bool>();
    g_Config.web_output = result["web"].as<bool>();
    g_Config.do_dllinjection_ucallstack = result["dllcallstack"].as<bool>();

    if (result["all"].as<bool>()) {
        g_Config.do_etw = true;
        g_Config.do_etwti = true;
        g_Config.do_kernelcallback = true;
        g_Config.do_dllinjection = true;
        g_Config.do_dllinjection_ucallstack = true;
    }
    else if (result.count("test")) {
        g_Config.targetExeName = "RedEdrTester.exe";
        std::string s = result["test"].as<std::string>();
        if (s == "etw") {
            g_Config.do_etw = true;
            g_Config.etw_standard = true;
            g_Config.etw_kernelaudit = false;
            g_Config.etw_secaudit = false;
            g_Config.etw_defender = false;
        }
        else if (s == "etwti") {
            g_Config.do_etwti = true;
        }
        else if (s == "kernel") {
            g_Config.do_kernelcallback = true;
        }
        else if (s == "dll") {
            g_Config.debug_dllreader = true;
        }
    } else if (result.count("replay")) {
        g_Config.replay_events = TRUE;
	} else if (!g_Config.do_etw && !g_Config.do_mplog && !g_Config.do_kernelcallback 
        && !g_Config.do_dllinjection && !g_Config.do_etwti && !g_Config.debug_dllreader) {
        printf("Choose at least one of --etw --etwti --kernel --inject --etwti (--dllreader for testing)");
        return 1;
    }

    // Event Record
    if (result.count("record")) {
        g_EventAggregator.InitRecorder(result["record"].as<std::string>());
    }

    CreateRequiredFiles();
    InitProcessQuery();
    g_EventProcessor.init(); // we also do it in constructor, but wont have g_Config

    // All threads of all *Reader subsystems
    std::vector<HANDLE> threads;
    LOG_A(LOG_INFO, "RedEdr %s", REDEDR_VERSION);
    LOG_A(LOG_INFO, "Tracing processes with name: %s", g_Config.targetExeName.c_str());

    // SeDebug
    if (!PermissionMakeMeDebug()) {
        LOG_A(LOG_ERROR, "RedEdr: Permission error - Did you start with local admin?");
        return 1;
    }
    if (!IsRunningAsSystem()) {
        LOG_A(LOG_WARNING, "RedEdr: Permission error - Not running as SYSTEM, some ETW data is not available");
    }

    // Ctrl+C
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        LOG_A(LOG_ERROR, "RedEdr: Failed to set control handler");
        return 1;
    }

    // Webserver
    if (g_Config.web_output) {
        InitializeWebServer(threads);
    }

    // Functionality
    ManagerStart(threads);
    InitKeyboardReader(threads);
    InitializeEventProcessor(threads);

    // Replay
    if (result.count("replay")) {
        ReplayEvents(result["replay"].as<std::string>());
    }

    // Test
    if(result.count("test")) {
        LOG_A(LOG_INFO, "Tester: wait 1");
        Sleep(1000);
        if (result["test"].as<std::string>() == "etw") {
            LOG_A(LOG_INFO, "Tester: wait 2");
            Sleep(3000); // let ETW warm up
        }
		g_Config.targetExeName = "RedEdrTester";

        LOG_A(LOG_INFO, "Tester: process in background");
        LPCWSTR path = L"C:\\RedEdr\\RedEdrTester.exe";
        LPCWSTR args = L"dostuff";
        DWORD pid = StartProcessInBackground(path, args);
        if (result["test"].as<std::string>() == "dll") {
            // do the userspace dll injection
            LOG_A(LOG_INFO, "Tester: Do DLL injection");
            remote_inject(pid);
        }
        LOG_A(LOG_INFO, "Tester: wait");
        for (int n = 0; n < 3; n++) {
            Sleep(1000); // give it time to do its thing

        }
        LOG_A(LOG_INFO, "Tester: Shutdown");
        ManagerShutdown();
        keyboard_reader_running = FALSE;
        Sleep(1000); // For log output
    }

    // Wait for all threads to complete
    LOG_A(LOG_INFO, "RedEdr: All started, waiting for %llu threads to exit", threads.size());
    DWORD res = WaitForMultipleObjects((DWORD) threads.size(), threads.data(), TRUE, INFINITE);
    if (res == WAIT_FAILED) {
        LOG_A(LOG_INFO, "RedEdr: Wait failed");
    }
    LOG_A(LOG_INFO, "RedEdr: all %llu threads finished", threads.size());
    return 0;
}