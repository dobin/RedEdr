#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

#include "../Shared/common.h"
#include "logging.h"
#include "kernelreader.h"
#include "piping.h"
#include "event_aggregator.h"

#pragma comment (lib, "wintrust.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")


// KernelReader: Reads events from the kernel pipe (from Kernel Callbacks)


// Private variables
HANDLE hStopEventKernel = NULL;     // signaled to request thread stop
HANDLE hKernelThreadHandle = NULL;   // stored thread handle for join/terminate
HANDLE kernel_pipe = NULL;
PipeServer* kernelPipeServer = NULL;
HANDLE threadReadynessKernel; // ready to accept clients

// Private functions
DWORD WINAPI KernelReaderProcessingThread(LPVOID param);


bool KernelReaderInit(std::vector<HANDLE>& threads) {
    hStopEventKernel = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (hStopEventKernel == NULL) {
        LOG_A(LOG_ERROR, "KernelReader: Failed to create stop event");
        return false;
    }
    threadReadynessKernel = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (threadReadynessKernel == NULL) {
        LOG_A(LOG_ERROR, "KernelReader: Failed to create event for thread readyness");
        CloseHandle(hStopEventKernel);
        hStopEventKernel = NULL;
        return false;
    }

    LOG_A(LOG_INFO, "!KernelReader: Start thread");
    HANDLE thread = CreateThread(NULL, 0, KernelReaderProcessingThread, NULL, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "KernelReader: Failed to create thread for trace session logreader");
        return false;
    }
    hKernelThreadHandle = thread;

    WaitForSingleObject(threadReadynessKernel, INFINITE);
    threads.push_back(thread);

    return true;
}


DWORD WINAPI KernelReaderProcessingThread(LPVOID param) {
    // Loop which accepts new clients
    while (WaitForSingleObject(hStopEventKernel, 0) != WAIT_OBJECT_0) {
        LOG_A(LOG_INFO, "KernelReader: Waiting for kernel");
        kernelPipeServer = new PipeServer("RedEdr KernelReader", (wchar_t*) KERNEL_PIPE_NAME);
        kernelPipeServer->Start(TRUE);
        SetEvent(threadReadynessKernel); // signal the event
        if (!kernelPipeServer->WaitForClient()) {
            LOG_A(LOG_ERROR, "KernelReader: WaitForClient failed");
            kernelPipeServer->Shutdown();
            continue;
        }
		LOG_A(LOG_INFO, "KernelReader: Kernel connected");
        while (WaitForSingleObject(hStopEventKernel, 0) != WAIT_OBJECT_0) {
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
    // Signal stop
    if (hStopEventKernel != NULL) {
        SetEvent(hStopEventKernel);
    }

    if (kernelPipeServer == NULL) {
        // Thread may be blocked in WaitForClient; unblock it with a fake connect
        try {
            PipeClient pipeClient("RedEdr KernelReaderShutdown");
            char buf[DATA_BUFFER_SIZE] = { 0 };
            const char* send = "";
            if (pipeClient.Connect(KERNEL_PIPE_NAME)) {
                pipeClient.Receive(buf, DATA_BUFFER_SIZE);
                pipeClient.Send((char*)send);
                pipeClient.Disconnect();
            }
        }
        catch (...) {}
    }
    else if (!kernelPipeServer->IsConnected()) {
        PipeClient pipeClient("RedEdr KernelReaderShutdown");
        char buf[DATA_BUFFER_SIZE] = { 0 };
        const char* send = "";
        if (pipeClient.Connect(KERNEL_PIPE_NAME)) {
            pipeClient.Receive(buf, DATA_BUFFER_SIZE);
            pipeClient.Send((char*)send);
            pipeClient.Disconnect();
        }
    }
    else {
        kernelPipeServer->Shutdown();
        delete kernelPipeServer;
        kernelPipeServer = NULL;
    }

    // Wait for thread to exit cleanly
    if (hKernelThreadHandle != NULL) {
        if (WaitForSingleObject(hKernelThreadHandle, 5000) == WAIT_TIMEOUT) {
            LOG_A(LOG_WARNING, "KernelReader: Thread did not exit in time, force-terminating");
            TerminateThread(hKernelThreadHandle, 1);
        }
        CloseHandle(hKernelThreadHandle);
        hKernelThreadHandle = NULL;
    }

    if (hStopEventKernel != NULL) {
        CloseHandle(hStopEventKernel);
        hStopEventKernel = NULL;
    }
}

