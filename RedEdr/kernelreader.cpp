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
#include "processcache.h"
#include "piping.h"
#include "eventproducer.h"

#pragma comment (lib, "wintrust.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")


// KernelReader: Reads events from the kernel pipe (from Kernel Callbacks)


// Private variables
bool KernelReaderThreadStopFlag = FALSE;
HANDLE kernel_pipe = NULL;
PipeServer* kernelPipeServer = NULL;
HANDLE threadReadyness; // ready to accept clients

// Private functions
DWORD WINAPI KernelReaderProcessingThread(LPVOID param);
void CheckEventForNewObservable(wchar_t* line);


void KernelReaderInit(std::vector<HANDLE>& threads) {
    const wchar_t* data = L"";
    threadReadyness = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (threadReadyness == NULL) {
		LOG_A(LOG_ERROR, "KernelReader: Failed to create event for thread readyness");
		return;
	}

    LOG_A(LOG_INFO, "!KernelReader: Start thread");
    HANDLE thread = CreateThread(NULL, 0, KernelReaderProcessingThread, (LPVOID)data, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "KernelReader: Failed to create thread for trace session logreader");
        return;
    }

    WaitForSingleObject(threadReadyness, INFINITE);
    threads.push_back(thread);
}


DWORD WINAPI KernelReaderProcessingThread(LPVOID param) {
    // Loop which accepts new clients
    while (!KernelReaderThreadStopFlag) {
        kernelPipeServer = new PipeServer(L"KernelReader");
        kernelPipeServer->Start(KERNEL_PIPE_NAME, TRUE);
        SetEvent(threadReadyness); // signal the event
        if (!kernelPipeServer->WaitForClient()) {
            LOG_A(LOG_ERROR, "KernelReader: WaitForClient failed");
            kernelPipeServer->Shutdown();
            continue;
        }

        while (!KernelReaderThreadStopFlag) {
            std::vector<std::wstring> events = kernelPipeServer->ReceiveBatch();
            if (events.empty()) {
                break;
            }
            for (const auto& event : events) {
                g_EventProducer.do_output(event);
                CheckEventForNewObservable((wchar_t*) event.c_str());
            }
        }

        kernelPipeServer->Shutdown();
        delete kernelPipeServer;
        kernelPipeServer = NULL;
    }

    LOG_A(LOG_INFO, "!DllReader Server Thread: end");
    return 0;
}


void CheckEventForNewObservable(wchar_t* line) {
    // Check if "observe:1" exists
    wchar_t* observe_str = wcsstr(line, L"observe:");
    if (!observe_str) {
        return;
    }

    // something like
    // "type:kernel;time:133711655617407173;callback:create_process;krn_pid:5564;pid:4240;name:\\Device\\HarddiskVolume2\\Windows\\System32\\notepad.exe;ppid:5564;parent_name:\\Device\\HarddiskVolume2\\Windows\\explorer.exe;observe:1"
    // find "observe:<int>" and pid from "pid:<int>"
    int observe_value = 0;
    swscanf_s(observe_str, L"observe:%d", &observe_value);
    if (observe_value == 1) {
        // Now extract the pid
        wchar_t* pid_str = wcsstr(line, L";pid:");
        if (pid_str) {
            int pid = 0;
            swscanf_s(pid_str, L";pid:%d", &pid);
            LOG_A(LOG_WARNING, "KernelReader: observe pid: %d (%d)", pid, observe_value);
            g_ProcessCache.getObject(pid); // FIXME this actually creates the process 
        }
    }
}


void KernelReaderShutdown() {
    KernelReaderThreadStopFlag = TRUE;

    if (! kernelPipeServer->IsConnected()) {
        PipeClient pipeClient;
        wchar_t buf[WCHAR_SMALL_PIPE] = { 0 };
        pipeClient.Connect(KERNEL_PIPE_NAME);
        pipeClient.Receive(buf, WCHAR_SMALL_PIPE);
        pipeClient.Send((wchar_t*)L"");
        pipeClient.Disconnect();
    }
    else {
        // Connected
        kernelPipeServer->Shutdown(); // if connected
        kernelPipeServer = NULL;
        delete kernelPipeServer;
    }
}

