#include <stdio.h>
#include <windows.h>
#include <cwchar>  // For wcstol
#include <cstdlib> // For exit()

#include "loguru.hpp"
#include "config.h"
#include "procinfo.h"
#include "dllinjector.h"


#define BUFFER_SIZE 1024
BOOL FakeKernelModulePipeServer() {
    DWORD bytesWritten;
    char buffer[BUFFER_SIZE] = "Hello from the server!";

    const wchar_t* pipeName = L"\\\\.\\pipe\\RedEdrKrnCom";
    HANDLE hPipe;
    while (TRUE) {
         hPipe = CreateNamedPipe(
            pipeName,                 // Pipe name to create
            PIPE_ACCESS_OUTBOUND,       // Whether the pipe is supposed to receive or send data (can be both)
            PIPE_TYPE_MESSAGE,        // Pipe mode (whether or not the pipe is waiting for data)
            PIPE_UNLIMITED_INSTANCES, // Maximum number of instances from 1 to PIPE_UNLIMITED_INSTANCES
            BUFFER_SIZE,             // Number of bytes for output buffer
            BUFFER_SIZE,             // Number of bytes for input buffer
            0,                        // Pipe timeout 
            NULL                      // Security attributes (anonymous connection or may be needs credentials. )
        );

        if (hPipe == INVALID_HANDLE_VALUE) {
            printf("Error creating named pipe: %ld\n", GetLastError());
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
            // Write data to the pipe
            if (!WriteFile(hPipe, buffer, (DWORD)strlen(buffer), &bytesWritten, NULL)) {
                if (GetLastError() == ERROR_NO_DATA) {
                    printf("Client disconnected, creating new socket\n");
                }
                else {
                    printf("Error writing from named pipe: %ld\n", GetLastError());
                }
                break;
            }

            Sleep(2000);
        }

        // Close the pipe
        CloseHandle(hPipe);
    }
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        printf("Usage: rededrtester.exe <pid>");
        return 1;
    }
    LOG_F(INFO, "RedTester");

    // Args: pid
    wchar_t* end;
    DWORD pid = wcstol(argv[1], &end, 10);

    // Tests
    
    // For testing the kernel callback handler: a pipe client
    FakeKernelModulePipeServer();
    // For testing the injected-dll: a pipe server
    //ConnectToServerPipe();
    // And manual DLL injection
    //remote_inject(pid);

    return 1;


    // Test: Process information
    Process* process = MakeProcess(pid);
    process->display();

    // Test: process name matching
    if (process->image_path.find(g_config.targetExeName) != std::wstring::npos) {
        wprintf(L"Observe CMD: %d %ls\n", pid, process->image_path.c_str());
    }
    else {
        wprintf(L"DONT Observe CMD: %d %ls\n", pid, process->image_path.c_str());
    }
}
