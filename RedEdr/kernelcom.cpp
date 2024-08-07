#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>


#include "kernelcom.h"

#pragma comment (lib, "wintrust.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "crypt32.lib")

#define MESSAGE_SIZE 2048

std::atomic<bool> KernelReaderThreadStopFlag(false);


void KernelReaderStopAll() {
    KernelReaderThreadStopFlag = TRUE;
}


DWORD WINAPI KernelReaderProcessingThread(LPVOID param) {
    const wchar_t* data = (wchar_t*)param;
    printf("--{ Start KernelReaderProcessingThread\n");
    ConnectToServerPipe();
    printf("--{ Stopped KernelReaderProcessingThread\n");
    return 0;
}


void InitializeKernelReader(std::vector<HANDLE>& threads) {
    const wchar_t* data = L"";
    HANDLE thread = CreateThread(NULL, 0, KernelReaderProcessingThread, (LPVOID)data, 0, NULL);
    if (thread == NULL) {
        std::wcerr << L"Failed to create thread for trace session logreader" << "" << std::endl;
        return;
    }
    threads.push_back(thread);

    //while (!KernelReaderThreadStopFlag) {
    //}
}


#define BUFFER_SIZE 1024
BOOL ConnectToServerPipe() {
    HANDLE hPipe;
    DWORD bytesRead;
    char buffer[BUFFER_SIZE];
    const wchar_t* pipeName = L"\\\\.\\pipe\\MyNamedPipe";

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
        printf("Error connecting to named pipe: %ld\n", GetLastError());
        return 1;
    }

    while (!KernelReaderThreadStopFlag) {
        // Read data from the pipe
        if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
            buffer[bytesRead] = '\0'; // Null-terminate the string
            printf("Received message: %s\n", buffer);
        }
        else {
            printf("Error reading from named pipe: %ld\n", GetLastError());
        }
    }

    // Close the pipe
    CloseHandle(hPipe);

    return 0;
}


int kernelcom() {
    LPCWSTR pipeName = L"\\\\.\\pipe\\dumbedr-analyzer";
    DWORD bytesRead = 0;
    wchar_t target_binary_file[MESSAGE_SIZE] = { 0 };

    printf("Launching analyzer named pipe server3\n");
    HANDLE hServerPipe;

    while (TRUE) {
        printf("Create Pipe\n");
        // Creates a named pipe
        hServerPipe = CreateNamedPipe(
            pipeName,                 // Pipe name to create
            PIPE_ACCESS_DUPLEX,       // Whether the pipe is supposed to receive or send data (can be both)
            PIPE_TYPE_MESSAGE,        // Pipe mode (whether or not the pipe is waiting for data)
            PIPE_UNLIMITED_INSTANCES, // Maximum number of instances from 1 to PIPE_UNLIMITED_INSTANCES
            MESSAGE_SIZE,             // Number of bytes for output buffer
            MESSAGE_SIZE,             // Number of bytes for input buffer
            0,                        // Pipe timeout 
            NULL                      // Security attributes (anonymous connection or may be needs credentials. )
        );

        // ConnectNamedPipe enables a named pipe server to start listening for incoming connections
        BOOL isPipeConnected = ConnectNamedPipe(
            hServerPipe, // Handle to the named pipe
            NULL         // Whether or not the pipe supports overlapped operations
        );

        BOOL ret;
        while (TRUE) {
            wchar_t message[MESSAGE_SIZE] = { 0 };
            if (isPipeConnected) {
                // Read from the named pipe
                ret = ReadFile(
                    hServerPipe,         // Handle to the named pipe
                    &message, // Target buffer where to stock the output
                    MESSAGE_SIZE,        // Size of the buffer
                    &bytesRead,          // Number of bytes read from ReadFile
                    NULL                 // Whether or not the pipe supports overlapped operations
                );

                if (not ret) {
                    printf("Broken pipe\n");
                    DisconnectNamedPipe(
                        hServerPipe // Handle to the named pipe
                    );
                    break;
                }
                else {
                    printf("~> %ws\n", message);
                }
            }
        }
    }

    printf("Exit\n\n");

    // Disconnect
    DisconnectNamedPipe(
        hServerPipe // Handle to the named pipe
    );

    return 0;
}