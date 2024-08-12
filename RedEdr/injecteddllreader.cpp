#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "loguru.hpp"
#include "injecteddllreader.h"


#define BUFFER_SIZE 1024

void InitializeInjectedDllReader(std::vector<HANDLE>& threads) {
}



BOOL InitializeInjectedDllReader2() {
    char buffer[BUFFER_SIZE] = "";
    DWORD bytesRead;

    const wchar_t* pipeName = L"\\\\.\\pipe\\MyNamedPipe";
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
            LOG_F(ERROR, "Error creating named pipe: %ld\n", GetLastError());
            return 1;
        }

        printf("Waiting for client to connect...\n");

        // Wait for the client to connect
        BOOL result = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!result) {
            printf("Error connecting to named pipe: %ld\n", GetLastError());
            CloseHandle(hPipe);
            return 1;
        }

        printf("Client connected.\n");

        while (TRUE) {
            // Read data from the pipe
            if (ReadFile(hPipe, buffer, BUFFER_SIZE, &bytesRead, NULL)) {
                buffer[BUFFER_SIZE-1] = '\0'; // Null-terminate the string
                LOG_F(INFO, "Received message len %d: %s", bytesRead, buffer);
            }
            else {
                if (GetLastError() == ERROR_BROKEN_PIPE) {
                    LOG_F(INFO, "Client disconnected: %ld", GetLastError());
                    break;
                }
                else {
                    LOG_F(ERROR, "Error reading from named pipe: %ld", GetLastError());
                    break;
                }
            }
        }

        // Close the pipe
        CloseHandle(hPipe);
    }
}
