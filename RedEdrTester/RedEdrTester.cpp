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
    //wchar_t buffer[DATA_BUFFER_SIZE] = L"Test:RedEdrTester:FakeDllPipeClient";
    wchar_t buffer[DATA_BUFFER_SIZE] = L"012345678901234567890123456789";
    HANDLE hPipe;
    int n = 0;
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
            //swprintf_s(buffer, sizeof(buffer), L"Test:RedEdrTester:FakeDllPipeClient:%d", n++);
            DWORD len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }
            printf("Wrote: %d\n", len);

            wcscat_s(buffer, L"A");
            len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier

            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }
            printf("Wrote: %d\n", len);

            wcscat_s(buffer, L"B");
            len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier

            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }
            printf("Wrote: %d\n", len);

            wcscat_s(buffer, L"C");
            len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier

            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }
            printf("Wrote: %d\n", len);

            wcscat_s(buffer, L"D");
            len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier

            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }
            printf("Wrote: %d\n", len);

            wcscat_s(buffer, L"E");
            len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
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


#define MAX 26 
void pipeparser_test() {
    const wchar_t* str[] = {
        L"XXXXXX",
        L"AAAAAAAA\0BBBB",
        L"BBBB\0CCCCCCCC",
        L"\0YYYYYY",
    };
    int lens[] = {
        14, 26, 26, 16
    };

    char buffer[1024];
    char* buf_ptr = buffer; // buf_ptr and rest_len are synchronized
    int rest_len = 0;       //

    for (int n = 0; n < 4; n++) {
        // PIPE READ
        int read_len = lens[n];
        memcpy_s(buf_ptr, 1024-rest_len, str[n], read_len);

        int full_len = rest_len + read_len; // full len including the previous shit, if any
        wchar_t* p = (wchar_t*) buffer; // pointer to the string we will print. points to buffer
                                        // which always contains the beginning of a string
        int last_potential_str_start = 0;
        for (int i = 0; i < full_len; i+=2) { // 2-byte increments because wide string
            if (buffer[i] == 0 && buffer[i + 1] == 0) { // check manually for \x00\x00
                wprintf(L"  -> %s\n", p); // found \x00\x00, print the previous string
                i += 2; // skip \x00\x00
                last_potential_str_start = i; // remember the last zero byte we found
                p = (wchar_t*) & buffer[i]; // init p with (potential) next string
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
}


int ioctl_enable_kernel_module() {
    HANDLE hDevice = CreateFile(L"\\\\.\\RedEdr",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("Failed to open device. Error: %d\n", GetLastError());
        return 1;
    }

    //char buffer[128] = "Hello kernel!";
    MY_DRIVER_DATA dataToSend = { 0 };
    wcscpy_s(dataToSend.filename, L"notepad.exe");
    dataToSend.flag = 1;

    char buffer_incoming[128] = {0};
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(hDevice,
        IOCTL_MY_IOCTL_CODE,
        (LPVOID)&dataToSend,
        (DWORD)sizeof(dataToSend),
        buffer_incoming,
        sizeof(buffer_incoming),
        &bytesReturned,
        NULL);
    if (!success) {
        printf("DeviceIoControl failed. Error: %d\n", GetLastError());
        CloseHandle(hDevice);
        return 1;
    }

    printf("Received from driver: %i: %s\n", bytesReturned, buffer_incoming);

    CloseHandle(hDevice);
    return 0;
}

int wmain(int argc, wchar_t* argv[]) {
    //pipeparser_test();
    //return 1;
    if (argc != 2) {
        printf("Usage: rededrtester.exe <pid>");
        return 1;
    }
    LOG_F(INFO, "RedTester");

    // Args: pid
    wchar_t* end;
    DWORD pid = wcstol(argv[1], &end, 10);

    int test = 3;
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
    case 5:
        printf("Pipeparser test\n");
        pipeparser_test();
        break;
    case 6:
        printf("IOCTL test\n");
        ioctl_enable_kernel_module();
    }
    


}
