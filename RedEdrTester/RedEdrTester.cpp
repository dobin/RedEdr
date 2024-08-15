#include <stdio.h>
#include <windows.h>
#include <cwchar>  // For wcstol
#include <cstdlib> // For exit()

#include "../Shared/common.h"
#include "loguru.hpp"
#include "config.h"
#include "procinfo.h"
#include "dllinjector.h"


// Will send some data to the RedEdr KernelModuleReader
BOOL FakeKernelPipeClient() {
    DWORD bytesWritten;
    wchar_t buffer[DATA_BUFFER_SIZE] = L"Test:RedEdrTester:FakeKernelPipeClient";
    HANDLE hPipe;
    while (TRUE) {
        hPipe = CreateFile(
            KERNEL_PIPE_NAME,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);
        if (hPipe == INVALID_HANDLE_VALUE) {
            printf("Error creating named pipe: %ld\n", GetLastError());
            return 1;
        }

        while (TRUE) {
            DWORD len = wcslen(buffer) * 2;
            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }

            Sleep(2000);
        }

        CloseHandle(hPipe);
    }
}


// Will send some data to the RedEdr DllReader
BOOL FakeDllPipeClient() {
    DWORD bytesWritten;
    wchar_t buffer[DATA_BUFFER_SIZE] = L"Test:RedEdrTester:FakeDllPipeClient";
    HANDLE hPipe;
    while (TRUE) {
        hPipe = CreateFile(
            DLL_PIPE_NAME,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);
        if (hPipe == INVALID_HANDLE_VALUE) {
            printf("Error creating named pipe: %ld\n", GetLastError());
            return 1;
        }

        while (TRUE) {
            DWORD len = wcslen(buffer) * 2;
            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }

            Sleep(2000);
        }

        CloseHandle(hPipe);
    }
}


void query_process(DWORD pid) {
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


int wmain(int argc, wchar_t* argv[]) {
    if (argc != 2) {
        printf("Usage: rededrtester.exe <pid>");
        return 1;
    }
    LOG_F(INFO, "RedTester");

    // Args: pid
    wchar_t* end;
    DWORD pid = wcstol(argv[1], &end, 10);

    int test = 2;
    switch (test) {
    case 1:
        printf("Fake Kernel Module Pipe Client\n");
        // Testing RedEdr kernel callback handler: a pipe client
        // For: RedEdr.exe --kernel
        FakeKernelPipeClient();
        break;

    case 2:
        printf("Fake InjectedDll Pipe Client\n");
        // Testing RedEdr InjectedDll callback handler: a pipe client
        // For: RedEdr.exe --inject
        FakeDllPipeClient();
        break;

    case 3:
        // And manual DLL injection
        printf("Manual DLL injection (from userspace)\n");
        remote_inject(pid);
        break;

    case 4:
        // Query process information
        printf("Query process information\n");
        query_process(pid);
        break;
    }
    


}
