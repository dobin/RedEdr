#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "loguru.hpp"
#include "kernelreader.h"

#pragma comment (lib, "wintrust.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")

#define BUFFER_SIZE 1024

std::atomic<bool> KernelReaderThreadStopFlag(false);
HANDLE hPipe = NULL;


void KernelReaderStopAll() {
    KernelReaderThreadStopFlag = TRUE;
}


DWORD WINAPI KernelReaderProcessingThread(LPVOID param) {
    char buffer[BUFFER_SIZE] = "";
    DWORD bytesRead;

    const wchar_t* pipeName = L"\\\\.\\pipe\\RedEdrKrnCom";
    HANDLE hPipe;
    while (!KernelReaderThreadStopFlag) {
        hPipe = CreateNamedPipe(
            pipeName,                 // Pipe name to create
            PIPE_ACCESS_INBOUND,       // Whether the pipe is supposed to receive or send data (can be both)
            PIPE_TYPE_MESSAGE,        // Pipe mode (whether or not the pipe is waiting for data)
            PIPE_UNLIMITED_INSTANCES, // Maximum number of instances from 1 to PIPE_UNLIMITED_INSTANCES
            BUFFER_SIZE,             // Number of bytes for output buffer
            BUFFER_SIZE,             // Number of bytes for input buffer
            0,                        // Pipe timeout 
            NULL                      // Security attributes (anonymous connection or may be needs credentials. )
        );
        if (hPipe == INVALID_HANDLE_VALUE) {
            LOG_F(ERROR, "KernelReader: Error creating named pipe: %ld", GetLastError());
            return 1;
        }

        LOG_F(INFO, "KernelReader: Waiting for client to connect...");

        // Wait for the client to connect
        BOOL result = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!result) {
            LOG_F(ERROR, "KernelReader: Error connecting to named pipe: %ld", GetLastError());
            CloseHandle(hPipe);
            return 1;
        }

        LOG_F(INFO, "KernelReader: Client connected.\n");

        while (!KernelReaderThreadStopFlag) {
            // Read data from the pipe
            if (ReadFile(hPipe, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
                buffer[BUFFER_SIZE - 1] = '\0'; // Null-terminate the string
                wprintf(L"KRN %i: %s\n", bytesRead, buffer);
            }
            else {
                if (GetLastError() == ERROR_BROKEN_PIPE) {
                    LOG_F(INFO, "KernelReader: Client disconnected: %ld", GetLastError());
                    break;
                }
                else {
                    LOG_F(ERROR, "KernelReader: Error reading from named pipe: %ld", GetLastError());
                    break;
                }
            }
        }

        // Close the pipe
        CloseHandle(hPipe);
    }
}



void InitializeKernelReader(std::vector<HANDLE>& threads) {
    const wchar_t* data = L"";
    HANDLE thread = CreateThread(NULL, 0, KernelReaderProcessingThread, (LPVOID)data, 0, NULL);
    if (thread == NULL) {
        LOG_F(ERROR, "KernelReader: Failed to create thread for trace session logreader");
        return;
    }
    threads.push_back(thread);
}
