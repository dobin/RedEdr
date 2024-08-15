#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "../Shared/common.h"
#include "loguru.hpp"
#include "kernelreader.h"

#pragma comment (lib, "wintrust.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")


std::atomic<bool> KernelReaderThreadStopFlag(false);
HANDLE hPipe = NULL;


void KernelReaderStopAll() {
    KernelReaderThreadStopFlag = TRUE;
}


DWORD WINAPI KernelReaderProcessingThread(LPVOID param) {
    char buffer[DATA_BUFFER_SIZE];
    char* buf_ptr = buffer; // buf_ptr and rest_len are synchronized
    int rest_len = 0;
    DWORD bytesRead;
    memset(buffer, 0, sizeof(buffer));
    HANDLE hPipe;

    while (!KernelReaderThreadStopFlag) {
        hPipe = CreateNamedPipe(
            KERNEL_PIPE_NAME,                 // Pipe name to create
            PIPE_ACCESS_INBOUND,       // Whether the pipe is supposed to receive or send data (can be both)
            PIPE_TYPE_MESSAGE,        // Pipe mode (whether or not the pipe is waiting for data)
            PIPE_UNLIMITED_INSTANCES, // Maximum number of instances from 1 to PIPE_UNLIMITED_INSTANCES
            PIPE_BUFFER_SIZE,             // Number of bytes for output buffer
            PIPE_BUFFER_SIZE,             // Number of bytes for input buffer
            0,                        // Pipe timeout 
            NULL                      // Security attributes (anonymous connection or may be needs credentials. )
        );
        if (hPipe == INVALID_HANDLE_VALUE) {
            LOG_F(ERROR, "KernelReader: Error creating named pipe: %ld", GetLastError());
            return 1;
        }

        LOG_F(INFO, "KernelReader: Waiting for client (Kernel Driver) to connect...");

        // Wait for the client to connect
        BOOL result = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!result) {
            LOG_F(ERROR, "KernelReader: Error connecting to named pipe: %ld", GetLastError());
            CloseHandle(hPipe);
            return 1;
        }

        LOG_F(INFO, "KernelReader: connected.\n");

        while (!KernelReaderThreadStopFlag) {
            // Read data from the pipe
            if (ReadFile(hPipe, buffer, DATA_BUFFER_SIZE, &bytesRead, NULL)) {
                int full_len = rest_len + bytesRead; // full len including the previous shit, if any
                wchar_t* p = (wchar_t*)buffer; // pointer to the string we will print. points to buffer
                // which always contains the beginning of a string
                int last_potential_str_start = 0;
                for (int i = 0; i < full_len; i += 2) { // 2-byte increments because wide string
                    if (buffer[i] == 0 && buffer[i + 1] == 0) { // check manually for \x00\x00
                        wprintf(L"KRN %i: %s\n", bytesRead, p); // found \x00\x00, print the previous string
                        i += 2; // skip \x00\x00
                        last_potential_str_start = i; // remember the last zero byte we found
                        p = (wchar_t*)&buffer[i]; // init p with (potential) next string
                    }
                }
                if (last_potential_str_start == 0) {
                    printf("No 0x00 0x00 byte found, errornous input?\n");
                }

                if (last_potential_str_start != full_len) {
                    // we didnt print until end of the buffer. so there's something left
                    rest_len = full_len - last_potential_str_start; // how much is left
                    memcpy(&buffer[0], &buffer[last_potential_str_start], rest_len); // copy that to the beginning of the buffer
                    buf_ptr = &buffer[rest_len]; // point read buffer to after our rest
                }
                else {
                    // printf till the end of the read data. 
                    // always reset
                    buf_ptr = &buffer[0];
                    rest_len = 0;
                }
            }
            else {
                if (GetLastError() == ERROR_BROKEN_PIPE) {
                    LOG_F(INFO, "KernelReader: Disconnected: %ld", GetLastError());
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
