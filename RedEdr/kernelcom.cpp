#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "loguru.hpp"
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
    LOG_F(INFO, "--{ Start KernelReaderProcessingThread");
    //ConnectToServerPipe();
    LOG_F(INFO, "--{ Stopped KernelReaderProcessingThread");
    return 0;
}


void InitializeKernelReader(std::vector<HANDLE>& threads) {
    const wchar_t* data = L"";
    HANDLE thread = CreateThread(NULL, 0, KernelReaderProcessingThread, (LPVOID)data, 0, NULL);
    if (thread == NULL) {
        LOG_F(ERROR, "Failed to create thread for trace session logreader");
        return;
    }
    threads.push_back(thread);

    //while (!KernelReaderThreadStopFlag) {
    //}
}




int kernelcom() {
    LPCWSTR pipeName = L"\\\\.\\pipe\\dumbedr-analyzer";
    DWORD bytesRead = 0;
    wchar_t target_binary_file[MESSAGE_SIZE] = { 0 };

    LOG_F(INFO, "Launching analyzer named pipe server3");
    HANDLE hServerPipe;

    while (TRUE) {
        LOG_F(INFO, "Create Pipe");
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
                    LOG_F(INFO, "Broken pipe");
                    DisconnectNamedPipe(
                        hServerPipe // Handle to the named pipe
                    );
                    break;
                }
                else {
                    wprintf(L"~> %ws\n", message);
                }
            }
        }
    }

    LOG_F(INFO, "KernelReader: Exit");

    // Disconnect
    DisconnectNamedPipe(
        hServerPipe // Handle to the named pipe
    );

    return 0;
}