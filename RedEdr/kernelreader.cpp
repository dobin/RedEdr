#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <wchar.h>
#include <mutex>
#include <condition_variable>
#include <thread>

#include "../Shared/common.h"
#include "logging.h"
#include "kernelreader.h"
#include "process_resolver.h"
#include "piping.h"
#include "event_aggregator.h"

#pragma comment (lib, "wintrust.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")


// KernelReader: Reads events from the kernel pipe (from Kernel Callbacks)


// Private variables
bool KernelReaderThreadStopFlag = FALSE;
HANDLE kernel_pipe = NULL;
PipeServer* kernelPipeServer = NULL;
HANDLE threadReadynessKernel; // ready to accept clients

// Private functions
DWORD WINAPI KernelReaderProcessingThread(LPVOID param);


bool KernelReaderInit(std::vector<HANDLE>& threads) {
    const wchar_t* data = L"";
    threadReadynessKernel = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (threadReadynessKernel == NULL) {
		LOG_A(LOG_ERROR, "KernelReader: Failed to create event for thread readyness");
		return false;
	}

    LOG_A(LOG_INFO, "!KernelReader: Start thread");
    HANDLE thread = CreateThread(NULL, 0, KernelReaderProcessingThread, (LPVOID)data, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "KernelReader: Failed to create thread for trace session logreader");
        return false;
    }

    WaitForSingleObject(threadReadynessKernel, INFINITE);
    threads.push_back(thread);

    return true;
}


DWORD WINAPI KernelReaderProcessingThread(LPVOID param) {
    // Loop which accepts new clients
    while (!KernelReaderThreadStopFlag) {
        LOG_A(LOG_INFO, "KernelReader: Waiting for kernel");
        kernelPipeServer = new PipeServer("KernelReader", (wchar_t*) KERNEL_PIPE_NAME);
        kernelPipeServer->Start(TRUE);
        SetEvent(threadReadynessKernel); // signal the event
        if (!kernelPipeServer->WaitForClient()) {
            LOG_A(LOG_ERROR, "KernelReader: WaitForClient failed");
            kernelPipeServer->Shutdown();
            continue;
        }
		LOG_A(LOG_INFO, "KernelReader: Kernel connected");
        while (!KernelReaderThreadStopFlag) {
            std::vector<std::string> events = kernelPipeServer->ReceiveBatch();
            if (events.empty()) {
                break;
            }
            for (const auto& event : events) {
                g_EventAggregator.NewEvent(event);
            }
        }

        kernelPipeServer->Shutdown();
        delete kernelPipeServer;
        kernelPipeServer = NULL;
    }

    LOG_A(LOG_INFO, "!DllReader Server Thread: end");
    return 0;
}


void KernelReaderShutdown() {
    KernelReaderThreadStopFlag = TRUE;

    if (! kernelPipeServer->IsConnected()) {
        PipeClient pipeClient;
        char buf[DATA_BUFFER_SIZE] = { 0 }; // We may receive a full event here
        const char *send = "";
        pipeClient.Connect(KERNEL_PIPE_NAME);
        pipeClient.Receive(buf, DATA_BUFFER_SIZE);
        pipeClient.Send((char*) send);
        pipeClient.Disconnect();
    }
    else {
        // Connected
        kernelPipeServer->Shutdown(); // if connected
        kernelPipeServer = NULL;
        delete kernelPipeServer;
    }
}

