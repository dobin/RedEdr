#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "loguru.hpp"
#include "injecteddllreader.h"


#define BUFFER_SIZE 1024


DWORD WINAPI DllInjectionReaderProcessingThread(LPVOID param) {
    char buffer[BUFFER_SIZE] = "";
    DWORD bytesRead;

    const wchar_t* pipeName = L"\\\\.\\pipe\\RedEdrDllCom";
    HANDLE hPipe;
    while (TRUE) {
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
            LOG_F(ERROR, "DllReader: Error creating named pipe: %ld", GetLastError());
            return 1;
        }

        LOG_F(INFO, "DllReader: Waiting for client to connect...");

        // Wait for the client to connect
        BOOL result = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!result) {
            LOG_F(ERROR, "DllReader: Error connecting to named pipe: %ld", GetLastError());
            CloseHandle(hPipe);
            return 1;
        }

        LOG_F(INFO, "DllReader: Client connected.\n");

        while (TRUE) {
            // Read data from the pipe
            if (ReadFile(hPipe, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
                buffer[BUFFER_SIZE-1] = '\0'; // Null-terminate the string
                LOG_F(INFO, "DLL %i: %s", bytesRead, buffer);
            }
            else {
                if (GetLastError() == ERROR_BROKEN_PIPE) {
                    LOG_F(INFO, "DllReader: Client disconnected: %ld", GetLastError());
                    break;
                }
                else {
                    LOG_F(ERROR, "DllReader: Error reading from named pipe: %ld", GetLastError());
                    break;
                }
            }
        }

        // Close the pipe
        CloseHandle(hPipe);
    }
}


void InitializeInjectedDllReader(std::vector<HANDLE>& threads) {
    const wchar_t* data = L"";
    HANDLE thread = CreateThread(NULL, 0, DllInjectionReaderProcessingThread, (LPVOID)data, 0, NULL);
    if (thread == NULL) {
        LOG_F(ERROR, "DllReader: Failed to create thread ");
        return;
    }
    threads.push_back(thread);
}
