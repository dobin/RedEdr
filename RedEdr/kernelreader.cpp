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

#define MESSAGE_SIZE 1024

std::atomic<bool> KernelReaderThreadStopFlag(false);
HANDLE hPipe = NULL;


void KernelReaderStopAll() {
    KernelReaderThreadStopFlag = TRUE;
}



DWORD WINAPI KernelReaderProcessingThread(LPVOID param) {
    LPCWSTR pipeName = L"\\\\.\\pipe\\RedEdrKrnCom";
    DWORD bytesRead = 0;
    wchar_t target_binary_file[MESSAGE_SIZE] = { 0 };
    char buffer[MESSAGE_SIZE] = "";
    LOG_F(INFO, "Launching Kernel Pipe Reader");
    
    while (!KernelReaderThreadStopFlag) {
        // Connect to the named pipe
        hPipe = CreateFile(
            pipeName,              // Pipe name
            GENERIC_READ,          // Write access
            0,                      // No sharing
            NULL,                   // Default security attributes
            OPEN_EXISTING,          // Opens existing pipe
            0,                      // Default attributes
            NULL);                  // No template file

        if (hPipe == INVALID_HANDLE_VALUE) {
            LOG_F(ERROR, "KernelReader: Invalid handle, could not connect to named pipe: %ld", GetLastError());
            return 1;
        }

        while (!KernelReaderThreadStopFlag) {
            // Read data from the pipe
            if (ReadFile(hPipe, buffer, MESSAGE_SIZE, &bytesRead, NULL)) {
                buffer[MESSAGE_SIZE - 1] = '\0'; // Null-terminate the string
                LOG_F(INFO, "Kernel %i: %s", bytesRead, buffer);
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
    }

    return 0;
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
