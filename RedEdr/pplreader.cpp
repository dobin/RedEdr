
#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

#include "../Shared/common.h"
#include "logging.h"
#include "pplreader.h"
#include "piping.h"
#include "event_aggregator.h"


// PplReader: Consumes events from PPL service (ETW-TI data)


// Private Variables
HANDLE hStopEventPpl = NULL;   // signaled to request thread stop
HANDLE hPplThreadHandle = NULL; // stored thread handle for join/terminate
HANDLE threadReadynessPpl;     // ready to accept clients


// Private Function Definitions
void PplReaderClient(PipeServer* pipeServer);
DWORD WINAPI PplReaderThread(LPVOID param);


// Init
bool PplReaderInit(std::vector<HANDLE>& threads) {
    hStopEventPpl = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hStopEventPpl == NULL) {
        LOG_A(LOG_ERROR, "PplReader: Failed to create stop event");
        return false;
    }
    threadReadynessPpl = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (threadReadynessPpl == NULL) {
        LOG_A(LOG_ERROR, "PplReader: Failed to create event for thread readiness");
        CloseHandle(hStopEventPpl);
        hStopEventPpl = NULL;
        return false;
    }

    HANDLE thread = CreateThread(NULL, 0, PplReaderThread, NULL, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "PplReader: Failed to create thread");
        CloseHandle(threadReadynessPpl);
        threadReadynessPpl = NULL;
        CloseHandle(hStopEventPpl);
        hStopEventPpl = NULL;
        return false;
    }
    hPplThreadHandle = thread;

    // Wait for the client to connect (PPL service should already be running)
    WaitForSingleObject(threadReadynessPpl, INFINITE);
    Sleep(200); // it has to bind() n stuff
    threads.push_back(thread);
    return true;
}


// Pipe Reader Thread: Server
DWORD WINAPI PplReaderThread(LPVOID param) {
    LOG_A(LOG_INFO, "!PplReaderThread: begin");

    // Loop which accepts new clients
    while (WaitForSingleObject(hStopEventPpl, 0) != WAIT_OBJECT_0) {
        PipeServer* pipeServer = new PipeServer("RedEdr PplReader", (wchar_t*) PPL_DATA_PIPE_NAME);
        if (pipeServer == nullptr) {
            LOG_A(LOG_ERROR, "PplReaderThread: Failed to create PipeServer");
            Sleep(1000); // Brief delay before retry
            continue;
        }
        // Signal that the thread is ready
        SetEvent(threadReadynessPpl);
        
        if (!pipeServer->StartAndWaitForClient(TRUE)) {
            LOG_A(LOG_ERROR, "PplReaderThread: Failed to start pipe server or wait for client");
            pipeServer->Shutdown();
            delete pipeServer;
            Sleep(1000); // Brief delay before retry
            continue;
        }

        LOG_A(LOG_INFO, "PplReaderThread: Client connected successfully");

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

    while (WaitForSingleObject(hStopEventPpl, 0) != WAIT_OBJECT_0) {
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

    // Signal stop
    if (hStopEventPpl != NULL) {
        SetEvent(hStopEventPpl);
    }

    // Cancel any blocking I/O (ReceiveBatch or ConnectNamedPipe) on the worker thread
    if (hPplThreadHandle != NULL) {
        CancelSynchronousIo(hPplThreadHandle);
    }

    // Wait for thread to exit cleanly
    if (hPplThreadHandle != NULL) {
        if (WaitForSingleObject(hPplThreadHandle, 5000) == WAIT_TIMEOUT) {
            LOG_A(LOG_WARNING, "PplReader: Thread did not exit in time, force-terminating");
            TerminateThread(hPplThreadHandle, 1);
        }
        CloseHandle(hPplThreadHandle);
        hPplThreadHandle = NULL;
    }

    // Close event handles
    if (hStopEventPpl != NULL) {
        CloseHandle(hStopEventPpl);
        hStopEventPpl = NULL;
    }
    if (threadReadynessPpl != NULL) {
        CloseHandle(threadReadynessPpl);
        threadReadynessPpl = NULL;
    }
}
