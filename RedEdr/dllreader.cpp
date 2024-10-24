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
#include "event_producer.h"


// Set to TRUE when shutting down client threads
bool DllReaderThreadStop = FALSE;

// Threads for each connected DLL process
std::vector<std::thread> DllReaderClientThreads; // for each connected dll client
std::vector<PipeServer*> DllReaderPipeServers; // for each connected dll client

// Private Function Definitions
void DllReaderInit(std::vector<HANDLE>& threads);
void DllReaderClientThread(PipeServer* pipeServer);
DWORD WINAPI DllReaderThread(LPVOID param);
void DllReaderShutdown();


// Init
void DllReaderInit(std::vector<HANDLE>& threads) {
    const wchar_t* data = L"";
    HANDLE thread = CreateThread(NULL, 0, DllReaderThread, NULL, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "DllReader: Failed to create thread");
        return;
    }
    threads.push_back(thread);
}


// Pipe Reader Thread: Server
DWORD WINAPI DllReaderThread(LPVOID param) {
    LOG_A(LOG_INFO, "!DllReader Server Thread: begin");

    // Loop which accepts new clients
    while (!DllReaderThreadStop) {
        PipeServer* pipeServer = new PipeServer(L"DllReader");
        if(! pipeServer->StartAndWaitForClient(DLL_PIPE_NAME, TRUE)) {
            LOG_A(LOG_ERROR, "WTF");
            pipeServer->Shutdown();
            delete pipeServer;
            continue;
        }

        LOG_A(LOG_INFO, "DllReader: Client connected (handle in new thread)");
        DllReaderClientThreads.push_back(std::thread(DllReaderClientThread, pipeServer));
    }
    
    // Wait for all client threads to exit
    for (auto& t : DllReaderClientThreads) {
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
    wchar_t config[WCHAR_SMALL_PIPE];
    swprintf_s(config, WCHAR_SMALL_PIPE, L"callstack:%d;", g_config.do_dllinjection_ucallstack);
    pipeServer->Send(config);

    // Now receive only
    char buffer[DATA_BUFFER_SIZE] = {0};
    char* buf_ptr = buffer; // buf_ptr and rest_len are synchronized
    int rest_len = 0;
    while (!DllReaderThreadStop) {
        std::vector<std::wstring> result = pipeServer->ReceiveBatch();
        if (result.empty()) {
            return;
        }
        for (const auto& wstr : result) {
            g_EventProducer.do_output(wstr);
        }
    }

    pipeServer->Shutdown();
    delete pipeServer;
}


// Shutdown
void DllReaderShutdown() {
    DllReaderThreadStop = TRUE;

    // Disconnect all connected client pipes
    for (auto& t : DllReaderPipeServers) {
        t->Shutdown();
    }

    // Disconnect server pipe
    // Send some stuff so the ReadFile() in the reader thread returns
    PipeClient pipeClient;
    wchar_t buf[WCHAR_SMALL_PIPE] = { 0 };
    pipeClient.Connect(DLL_PIPE_NAME);
    pipeClient.Receive(buf, WCHAR_SMALL_PIPE);
    pipeClient.Send((wchar_t *) L"");
    pipeClient.Disconnect();
}

