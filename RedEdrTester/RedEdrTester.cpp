#include <stdio.h>
#include <windows.h>
#include <cwchar>  // For wcstol
#include <cstdlib> // For exit()

#include <string>
#include <sstream>
//#include <map>
#include <vector>


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


int LoadDriver() {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    int result = 0;
    LPCWSTR driverName = g_config.driverName;
    LPCWSTR driverPath = g_config.driverPath;

    // Open the Service Control Manager
    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        printf("OpenSCManager failed. Error: %lu\n", GetLastError());
        return 1;
    }

    // Create the service (driver)
    hService = CreateService(
        hSCManager,              // SCM handle
        driverName,              // Name of the service
        driverName,              // Display name
        SERVICE_ALL_ACCESS,      // Desired access
        SERVICE_KERNEL_DRIVER,   // Service type (kernel driver)
        SERVICE_DEMAND_START,    // Start type (on demand)
        SERVICE_ERROR_NORMAL,    // Error control type
        driverPath,              // Path to the driver executable
        NULL,                    // No load ordering group
        NULL,                    // No tag identifier
        NULL,                    // No dependencies
        NULL,                    // LocalSystem account
        NULL                     // No password
    );

    if (!hService) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            printf("Service already exists. Opening existing service...\n");
            hService = OpenService(hSCManager, driverName, SERVICE_ALL_ACCESS);
            if (!hService) {
                printf("OpenService failed. Error: %lu\n", GetLastError());
                result = 1;
                goto cleanup;
            }
        }
        else {
            printf("CreateService failed. Error: %lu\n", GetLastError());
            result = 1;
            goto cleanup;
        }
    }

    // Start the service (load the driver)
    if (!StartService(hService, 0, NULL)) {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            printf("StartService failed. Error: %lu\n", GetLastError());
            result = 1;
            goto cleanup;
        }
        else {
            printf("Service already running.\n");
        }
    }
    else {
        printf("Service started successfully.\n");
    }

cleanup:
    if (hService) CloseServiceHandle(hService);
    if (hSCManager) CloseServiceHandle(hSCManager);

    return result;
}


int UnloadDriver() {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS status;
    int result = 0;
    LPCWSTR driverName = g_config.driverName;

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        printf("OpenSCManager failed. Error: %lu\n", GetLastError());
        return 1;
    }

    hService = OpenService(hSCManager, driverName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!hService) {
        printf("OpenService failed. Error: %lu\n", GetLastError());
        result = 1;
        goto cleanup;
    }

    if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        printf("Service stopped successfully.\n");
    }
    else if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
        printf("Service is not running.\n");
    }
    else {
        printf("ControlService failed. Error: %lu\n", GetLastError());
        result = 1;
        goto cleanup;
    }

    if (!DeleteService(hService)) {
        printf("DeleteService failed. Error: %lu\n", GetLastError());
        result = 1;
        goto cleanup;
    }
    else {
        printf("Service deleted successfully.\n");
    }

cleanup:
    if (hService) CloseServiceHandle(hService);
    if (hSCManager) CloseServiceHandle(hSCManager);

    return result;
}

void DriverIsLoaded() {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    LPCWSTR driverName = g_config.driverName;

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        printf("OpenSCManager failed. Error: %lu\n", GetLastError());
        return;
    }

    hService = OpenService(hSCManager, driverName, SERVICE_QUERY_STATUS);
    if (!hService) {
        printf("OpenService failed. Error: %lu\n", GetLastError());
        goto cleanup;
    }

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        printf("Service status:\n");
        printf("  PID: %lu\n", status.dwProcessId);
        printf("  State: %lu\n", status.dwCurrentState);
    }
    else {
        printf("QueryServiceStatusEx failed. Error: %lu\n", GetLastError());
    }

cleanup:
    if (hService) CloseServiceHandle(hService);
    if (hSCManager) CloseServiceHandle(hSCManager);
}



LARGE_INTEGER get_time2() {
    FILETIME fileTime;
    LARGE_INTEGER largeInt;

    // Get the current system time as FILETIME
    GetSystemTimeAsFileTime(&fileTime);

    // Convert FILETIME to LARGE_INTEGER
    largeInt.LowPart = fileTime.dwLowDateTime;
    largeInt.HighPart = fileTime.dwHighDateTime;

    return largeInt;
}

std::wstring ConvertToJSON2(const std::wstring& input)
{
    std::vector<std::pair<std::wstring, std::wstring>> keyValuePairs;
    std::wstringstream wss(input);
    std::wstring token;

    // Split by ';'
    while (std::getline(wss, token, L';'))
    {
        std::wstringstream kvStream(token);
        std::wstring key, value;

        // Split by ':'
        if (std::getline(kvStream, key, L':') && std::getline(kvStream, value))
        {
            keyValuePairs.emplace_back(key, value);
        }
    }

    // Construct JSON
    std::wstringstream jsonStream;
    jsonStream << L"{";

    bool first = true;
    for (const auto& pair : keyValuePairs)
    {
        if (!first)
        {
            jsonStream << L", ";
        }
        jsonStream << L"\"" << pair.first << L"\": \"" << pair.second << L"\"";
        first = false;
    }

    jsonStream << L"}";

    return jsonStream.str();
}


void ConvertLargeIntegerToReadableString2(LARGE_INTEGER largeInt, char* buffer, size_t bufferSize)
{
    FILETIME fileTime;
    SYSTEMTIME systemTime;

    // Assign LARGE_INTEGER to FILETIME
    fileTime.dwLowDateTime = largeInt.LowPart;
    fileTime.dwHighDateTime = largeInt.HighPart;

    // Convert FILETIME to SYSTEMTIME
    FileTimeToSystemTime(&fileTime, &systemTime);

    // Format SYSTEMTIME to a readable string
    // In UTC
    snprintf(buffer, bufferSize,
        "%04d-%02d-%02d %02d:%02d:%02d.%03d",
        systemTime.wYear,
        systemTime.wMonth,
        systemTime.wDay,
        systemTime.wHour,
        systemTime.wMinute,
        systemTime.wSecond,
        systemTime.wMilliseconds);

}


int wmain(int argc, wchar_t* argv[]) {
    if (argc != 3) {
        printf("Usage: rededrtester.exe <id> <pid>");
        return 1;
    }
    LOG_F(INFO, "RedTester");

    // Args: pid, for 3
    wchar_t* end;
    DWORD test = wcstol(argv[1], &end, 10);
    DWORD pid = wcstol(argv[2], &end, 10);

    //int test = 9;
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
        break;
    case 7:
        if (LoadDriver() == 0) {
            printf("Driver loaded successfully.\n");
        }
        else {
            printf("Failed to load driver.\n");
            return 1;
        }

        DriverIsLoaded();

        if (UnloadDriver() == 0) {
            printf("Driver unloaded successfully.\n");
        }
        else {
            printf("Failed to unload driver.\n");
            return 1;
        }
        break;
    case 8:
        char timeString[100];
        LARGE_INTEGER largeInt;
        largeInt = get_time2();
        printf("Time: %lld\n", largeInt);
        ConvertLargeIntegerToReadableString2(largeInt, timeString, sizeof(timeString));
        printf("Readable Time: %s\n", timeString);
        break;
    case 9:
        std::wstring input = L"type:dll;time:28500;krn_pid:133695059491286994;func:AllocateVirtualMemory;pid:FFFFFFFFFFFFFFFF;addr:0000004F821FCB60;zero:0x7fffffff;size:42;type:0x1000:protect:0x4";
        std::wstring json = ConvertToJSON2(input);
        std::wcout << L"JSON Output: " << json << std::endl;
        break;
    }
    


}
