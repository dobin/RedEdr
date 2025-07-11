
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

#include "../Shared/common.h"
#include "logging.h"
#include "pplreader.h"
#include "utils.h"
#include "config.h"
#include "piping.h"
#include "event_aggregator.h"


// PplReader: Consumes events from PPL service (ETW-TI data)


// Private Variables
std::vector<std::thread> ConnectedPplReaderThreads; // for each connected ppl service
bool PplReaderThreadStop = FALSE; // set to true to stop the server thread
HANDLE threadReadynessPpl; // ready to accept clients


// Private Function Definitions
void PplReaderClientThread(PipeServer* pipeServer);
DWORD WINAPI PplReaderThread(LPVOID param);


// Init
bool PplReaderInit(std::vector<HANDLE>& threads) {
    const wchar_t* data = L"";
    threadReadynessPpl = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (threadReadynessPpl == NULL) {
        LOG_A(LOG_ERROR, "PplReader: Failed to create event for thread readiness");
        return false;
    }

    HANDLE thread = CreateThread(NULL, 0, PplReaderThread, NULL, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "PplReader: Failed to create thread");
        return false;
    }

    WaitForSingleObject(threadReadynessPpl, INFINITE);
    threads.push_back(thread);
    return true;
}


// Pipe Reader Thread: Server
DWORD WINAPI PplReaderThread(LPVOID param) {
    LOG_A(LOG_INFO, "!PplReader Server Thread: begin");

    // Loop which accepts new clients
    while (!PplReaderThreadStop) {
        PipeServer* pipeServer = new PipeServer("PplReader", (wchar_t*) PPL_DATA_PIPE_NAME);
        if (pipeServer == nullptr) {
            LOG_A(LOG_ERROR, "PplReader: Failed to create PipeServer");
            Sleep(1000); // Brief delay before retry
            continue;
        }
        
        SetEvent(threadReadynessPpl);
        
        if (!pipeServer->StartAndWaitForClient(TRUE)) {
            LOG_A(LOG_ERROR, "PplReader: Failed to start pipe server or wait for client");
            pipeServer->Shutdown();
            delete pipeServer;
            Sleep(1000); // Brief delay before retry
            continue;
        }

        LOG_A(LOG_INFO, "PplReader: PPL Service connected (handle in new thread)");
        try {
            ConnectedPplReaderThreads.push_back(std::thread(PplReaderClientThread, pipeServer));
        }
        catch (const std::exception& e) {
            LOG_A(LOG_ERROR, "PplReader: Failed to create client thread: %s", e.what());
            pipeServer->Shutdown();
            delete pipeServer;
        }
    }
    
    // Wait for all client threads to exit
    for (auto& t : ConnectedPplReaderThreads) {
        if (t.joinable()) {
            t.join();
        }
    }

    LOG_A(LOG_INFO, "!PplReader Server Thread: end");
    return 0;
}


// Pipe Reader Thread: Process Client
void PplReaderClientThread(PipeServer* pipeServer) {
    if (pipeServer == nullptr) {
        LOG_A(LOG_ERROR, "PplReaderClientThread: pipeServer is null");
        return;
    }
    
    // Send config as first packet
    // This is the only write for this pipe
    char config[PPL_CONFIG_LEN];
    int result = sprintf_s(config, PPL_CONFIG_LEN, "ppl_events: 1; ");
    if (result < 0) {
        LOG_A(LOG_ERROR, "PplReaderClientThread: Failed to format config string");
        pipeServer->Shutdown();
        delete pipeServer;
        return;
    }
    
    if (!pipeServer->Send(config)) {
        LOG_A(LOG_ERROR, "PplReaderClientThread: Failed to send config");
        pipeServer->Shutdown();
        delete pipeServer;
        return;
    }

    LOG_A(LOG_INFO, "PplReader: Config sent to PPL service, starting event reception");

    // Now receive only
    while (!PplReaderThreadStop) {
        try {
            std::vector<std::string> results = pipeServer->ReceiveBatch();
            if (results.empty()) {
                LOG_A(LOG_INFO, "PplReader: PPL service disconnected");
                break; // Client disconnected or error
            }
            for (const auto& result : results) {
                if (!result.empty()) {
                    LOG_A(LOG_DEBUG, "PplReader: Received PPL event: %s", result.c_str());
                    g_EventAggregator.NewEvent(result);
                }
            }
        }
        catch (...) {
            LOG_A(LOG_ERROR, "PplReaderClientThread: Exception in receive loop");
            break;
        }
    }

    pipeServer->Shutdown();
    delete pipeServer;
}


// Shutdown
void PplReaderShutdown() {
    PplReaderThreadStop = TRUE;

    // Disconnect server pipe
    // Send some stuff so the ReadFile() in the reader thread returns
    try {
        PipeClient pipeClient;
        char buf[PPL_CONFIG_LEN] = { 0 };
        const char* s = "";
        
        if (pipeClient.Connect(PPL_DATA_PIPE_NAME)) {
            pipeClient.Receive(buf, PPL_CONFIG_LEN);
            pipeClient.Send((char *)s);
            pipeClient.Disconnect();
        }
    }
    catch (...) {
        LOG_A(LOG_WARNING, "PplReaderShutdown: Exception during pipe cleanup");
    }
    
    // Close event handle
    if (threadReadynessPpl != NULL) {
        CloseHandle(threadReadynessPpl);
        threadReadynessPpl = NULL;
    }
}
