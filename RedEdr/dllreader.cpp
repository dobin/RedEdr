#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <cwchar>
#include <cstdio>
#include <sddl.h>
#include <iostream>
#include <thread>
#include <vector>
#include <stdio.h>
#include <memory>

#include "../Shared/common.h"
#include "logging.h"
#include "dllreader.h"
#include "utils.h"
#include "config.h"
#include "piping.h"
#include "event_aggregator.h"


// DllReader: Consumes events from injected DLL hooks


// Private Variables
std::vector<std::thread> ConnectedDllReaderThreads; // for each connected dll
bool DllReaderThreadStop = FALSE; // set to true to stop the server thread
HANDLE threadReadynessDll; // ready to accept clients


// Private Function Definitions
void DllReaderInit(std::vector<HANDLE>& threads);
void DllReaderClientThread(PipeServer* pipeServer);
DWORD WINAPI DllReaderThread(LPVOID param);
void DllReaderShutdown();


// Init
void DllReaderInit(std::vector<HANDLE>& threads) {
    const wchar_t* data = L"";
    threadReadynessDll = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (threadReadynessDll == NULL) {
        LOG_A(LOG_ERROR, "DllReader: Failed to create event for thread readyness");
        return;
    }

    HANDLE thread = CreateThread(NULL, 0, DllReaderThread, NULL, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "DllReader: Failed to create thread");
        return;
    }

    WaitForSingleObject(threadReadynessDll, INFINITE);
    threads.push_back(thread);
}


// Pipe Reader Thread: Server
DWORD WINAPI DllReaderThread(LPVOID param) {
    LOG_A(LOG_INFO, "!DllReader Server Thread: begin");

    // Loop which accepts new clients
    while (!DllReaderThreadStop) {
        std::unique_ptr<PipeServer> pipeServer = std::make_unique<PipeServer>("DllReader", (wchar_t*) DLL_PIPE_NAME);
        if (!pipeServer) {
            LOG_A(LOG_ERROR, "DllReader: Failed to create PipeServer");
            Sleep(1000); // Brief delay before retry
            continue;
        }
        
        SetEvent(threadReadynessDll);
        
        if (!pipeServer->StartAndWaitForClient(TRUE)) {
            LOG_A(LOG_ERROR, "DllReader: Failed to start pipe server or wait for client");
            pipeServer->Shutdown();
            Sleep(1000); // Brief delay before retry
            continue;
        }

        LOG_A(LOG_INFO, "DllReader: Client connected (handle in new thread)");
        try {
            // Transfer ownership to the thread
            PipeServer* rawPtr = pipeServer.release();
            ConnectedDllReaderThreads.push_back(std::thread(DllReaderClientThread, rawPtr));
        }
        catch (const std::exception& e) {
            LOG_A(LOG_ERROR, "DllReader: Failed to create client thread: %s", e.what());
            pipeServer->Shutdown();
        }
    }
    
    // Wait for all client threads to exit
    for (auto& t : ConnectedDllReaderThreads) {
        if (t.joinable()) {
            t.join();
        }
    }

    LOG_A(LOG_INFO, "!DllReader Server Thread: end");
    return 0;
}


// Pipe Reader Thread: Process Client
void DllReaderClientThread(PipeServer* pipeServer) {
    // Use RAII to ensure cleanup
    std::unique_ptr<PipeServer> server(pipeServer);
    
    if (!server) {
        LOG_A(LOG_ERROR, "DllReaderClientThread: pipeServer is null");
        return;
    }
    
    try {
        // send config as first packet
        //   this is the only write for this pipe
        char config[DLL_CONFIG_LEN];
        int result = sprintf_s(config, DLL_CONFIG_LEN, "callstack: %d; ", g_Config.do_dllinjection_ucallstack ? 1 : 0);
        if (result < 0) {
            LOG_A(LOG_ERROR, "DllReaderClientThread: Failed to format config string");
            return;
        }
        
        if (!server->Send(config)) {
            LOG_A(LOG_ERROR, "DllReaderClientThread: Failed to send config");
            return;
        }

        // Now receive only
        while (!DllReaderThreadStop) {
            std::vector<std::string> results = server->ReceiveBatch();
            if (results.empty()) {
                break; // Client disconnected or error
            }
            for (const auto& result : results) {
                if (!result.empty()) {
                    g_EventAggregator.NewEvent(result);
                }
            }
        }
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "DllReaderClientThread: Exception in client processing: %s", e.what());
    }
    catch (...) {
        LOG_A(LOG_ERROR, "DllReaderClientThread: Unknown exception in client processing");
    }

    server->Shutdown();
    // server automatically deleted when unique_ptr goes out of scope
}
}


// Shutdown
void DllReaderShutdown() {
    DllReaderThreadStop = TRUE;

    // Disconnect server pipe
    // Send some stuff so the ReadFile() in the reader thread returns
    try {
        PipeClient pipeClient;
        char buf[DLL_CONFIG_LEN] = { 0 };
        const char* s = "";
        
        if (pipeClient.Connect(DLL_PIPE_NAME)) {
            pipeClient.Receive(buf, DLL_CONFIG_LEN);
            pipeClient.Send((char *)s);
            pipeClient.Disconnect();
        }
    }
    catch (const std::exception& e) {
        LOG_A(LOG_WARNING, "DllReaderShutdown: Exception during pipe cleanup: %s", e.what());
    }
    catch (...) {
        LOG_A(LOG_WARNING, "DllReaderShutdown: Unknown exception during pipe cleanup");
    }
    
    // Close event handle
    if (threadReadynessDll != NULL) {
        CloseHandle(threadReadynessDll);
        threadReadynessDll = NULL;
    }
}

