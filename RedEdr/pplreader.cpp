
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
bool PplReaderThreadStop = FALSE; // set to true to stop the server thread
HANDLE threadReadynessPpl; // ready to accept clients


// Private Function Definitions
void PplReaderClient(PipeServer* pipeServer);
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
    LOG_A(LOG_INFO, "!PplReaderThread: begin");

    // Loop which accepts new clients
    while (!PplReaderThreadStop) {
        PipeServer* pipeServer = new PipeServer("PplReader", (wchar_t*) PPL_DATA_PIPE_NAME);
        if (pipeServer == nullptr) {
            LOG_A(LOG_ERROR, "PplReaderThread: Failed to create PipeServer");
            Sleep(1000); // Brief delay before retry
            continue;
        }
        
        SetEvent(threadReadynessPpl);
        
        if (!pipeServer->StartAndWaitForClient(TRUE)) {
            LOG_A(LOG_ERROR, "PplReaderThread: Failed to start pipe server or wait for client");
            pipeServer->Shutdown();
            delete pipeServer;
            Sleep(1000); // Brief delay before retry
            continue;
        }

        // Handle it here
        PplReaderClient(pipeServer);

        // We finished
        LOG_A(LOG_INFO, "PplReaderThread: Client disconnected, shutting down this pipe");
        pipeServer->Shutdown();
        delete pipeServer;
    }
    
    LOG_A(LOG_INFO, "!PplReaderThreadd: end");
    return 0;
}


// Pipe Reader Thread: Process Client
void PplReaderClient(PipeServer* pipeServer) {
    if (pipeServer == nullptr) {
        LOG_A(LOG_ERROR, "PplReaderClient: pipeServer is null");
        return;
    }
    LOG_A(LOG_INFO, "PplReaderClient: RedEdrPplService connected successful, starting event reception");

    while (!PplReaderThreadStop) {
        try {
            std::vector<std::string> results = pipeServer->ReceiveBatch();
            if (results.empty()) {
                LOG_A(LOG_INFO, "PplReaderClient: PPL service disconnected");
                break; // Client disconnected or error
            }
            for (const auto& result : results) {
                if (!result.empty()) {
                    //LOG_A(LOG_DEBUG, "PplReader: Received PPL event: %s", result.c_str());
                    g_EventAggregator.NewEvent(result);
                }
            }
        }
        catch (...) {
            LOG_A(LOG_ERROR, "PplReaderClient: Exception in receive loop");
            break;
        }
    }
}


// Shutdown
void PplReaderShutdown() {
    LOG_A(LOG_INFO, "PPLReader: Shutdown");
    PplReaderThreadStop = TRUE;
    
    // Close event handle
    if (threadReadynessPpl != NULL) {
        CloseHandle(threadReadynessPpl);
        threadReadynessPpl = NULL;
    }
}
