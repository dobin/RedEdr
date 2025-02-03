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
        PipeServer* pipeServer = new PipeServer("DllReader", (wchar_t*) DLL_PIPE_NAME);
        SetEvent(threadReadynessDll);
        if(! pipeServer->StartAndWaitForClient(TRUE)) {
            LOG_A(LOG_ERROR, "WTF");
            pipeServer->Shutdown();
            delete pipeServer;
            continue;
        }

        LOG_A(LOG_INFO, "DllReader: Client connected (handle in new thread)");
        ConnectedDllReaderThreads.push_back(std::thread(DllReaderClientThread, pipeServer));
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
    // send config as first packet
    //   this is the only write for this pipe
    char config[DLL_CONFIG_LEN];
    sprintf_s(config, DLL_CONFIG_LEN, "callstack: % d; ", g_Config.do_dllinjection_ucallstack);
    pipeServer->Send(config);

    // Now receive only
    while (!DllReaderThreadStop) {
        std::vector<std::string> results = pipeServer->ReceiveBatch();
        if (results.empty()) {
            return;
        }
        for (const auto& result : results) {
           g_EventAggregator.NewEvent(result);
        }
    }

    pipeServer->Shutdown();
    delete pipeServer;
}


// Shutdown
void DllReaderShutdown() {
    DllReaderThreadStop = TRUE;

    // Disconnect server pipe
    // Send some stuff so the ReadFile() in the reader thread returns
    PipeClient pipeClient;
    char buf[DLL_CONFIG_LEN] = { 0 };
    const char* s = "";
    pipeClient.Connect(DLL_PIPE_NAME);
    pipeClient.Receive(buf, DLL_CONFIG_LEN);
    pipeClient.Send((char *)s);
    pipeClient.Disconnect();
}

