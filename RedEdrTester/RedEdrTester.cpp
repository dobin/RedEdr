

#include <stdio.h>
#include <windows.h>
#include <cwchar>  // For wcstol
#include <cstdlib> // For exit()

#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <iostream>

#include <wchar.h>
#include <stdio.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include "../Shared/common.h"
#include "logging.h"
#include "config.h"
#include "processinfo.h"
#include "dllinjector.h"
#include "analyzer.h"
#include "webserver.h"
#include "processcache.h"
#include "analyzer.h"

#pragma comment(lib, "Dbghelp.lib")


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
    Process* process = MakeProcess(pid, L"");
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
        memcpy_s(buf_ptr, 1024 - rest_len, str[n], read_len);

        int full_len = rest_len + read_len; // full len including the previous shit, if any
        wchar_t* p = (wchar_t*)buffer; // pointer to the string we will print. points to buffer
        // which always contains the beginning of a string
        int last_potential_str_start = 0;
        for (int i = 0; i < full_len; i += 2) { // 2-byte increments because wide string
            if (buffer[i] == 0 && buffer[i + 1] == 0) { // check manually for \x00\x00
                wprintf(L"  -> %s\n", p); // found \x00\x00, print the previous string
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
    dataToSend.enable = 1;
    dataToSend.dll_inject = 0;

    char buffer_incoming[128] = { 0 };
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



std::wstring format_wstring2(const wchar_t* format, ...) {
    wchar_t buffer[DATA_BUFFER_SIZE];

    va_list args;
    va_start(args, format);
    vswprintf(buffer, DATA_BUFFER_SIZE, format, args);
    va_end(args);

    return std::wstring(buffer);
}


char* GetMemoryPermissions(char* buf, DWORD protection) {
    //char permissions[4] = "---"; // Initialize as "---"
    strcpy_s(buf, 16, "---");

    if (protection & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[0] = 'R'; // Readable
    }
    if (protection & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[1] = 'W'; // Writable
    }
    if (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[2] = 'X'; // Executable
    }

    return buf;
}



// Will send some data to the RedEdr DllReader
BOOL FakePplPipeClient() {
    DWORD bytesWritten;
    //wchar_t buffer[DATA_BUFFER_SIZE] = L"Test:RedEdrTester:FakeDllPipeClient";
    wchar_t buffer[DATA_BUFFER_SIZE] = L"012345678901234567890123456789";
    HANDLE hPipe;
    int n = 0;
    while (TRUE) {
        hPipe = CreateFile(
            PPL_SERVICE_PIPE_NAME,
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
        DWORD len;
        //        while (TRUE) {
        if (1) {
            //swprintf_s(buffer, sizeof(buffer), L"Test:RedEdrTester:FakeDllPipeClient:%d", n++);
            wcscpy_s(buffer, DATA_BUFFER_SIZE, L"start");
            len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }
            wprintf(L"Wrote: %s\n", buffer);
            Sleep(10000);

            /*wcscpy_s(buffer, DATA_BUFFER_SIZE, L"TESCHT");
            len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }
            printf("Wrote: %d\n", len);
            Sleep(1000);

            wcscpy_s(buffer, DATA_BUFFER_SIZE, L"TESCHT2");
            len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }
            printf("Wrote: %d\n", len);
            Sleep(1000);*/

            wcscpy_s(buffer, DATA_BUFFER_SIZE, L"stop");
            len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }
            wprintf(L"Wrote: %s\n", buffer);
            Sleep(1000);
            //} else {
            wcscpy_s(buffer, DATA_BUFFER_SIZE, L"shutdown");
            len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
            if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
                printf("Error writing to named pipe: %ld\n", GetLastError());
                CloseHandle(hPipe);
                return 1;
            }
            wprintf(L"Wrote: %s\n", buffer);

        }
        //        }

        CloseHandle(hPipe);
    }
}




DWORD start_child_process(wchar_t* childCMD)
{
    DWORD retval = 0;
    //WCHAR childCMD[MAX_BUF_SIZE] = { 0 };
    DWORD dataSize = MAX_BUF_SIZE;
    wprintf(L"[PPL_RUNNER] start_child_process: Starting");

    // Get Command to run from registry
    //LOG_W(LOG_INFO, L"[PPL_RUNNER] start_child_process: Looking for command in RegKey: HKLM\\%s\n", CMD_REGKEY);
    //retval = RegGetValue(HKEY_LOCAL_MACHINE, CMD_REGKEY, NULL, RRF_RT_REG_SZ, NULL, &childCMD, &dataSize);
    //if (retval != ERROR_SUCCESS) {
    //    LOG_W(LOG_INFO, L"[PPL_RUNNER] start_child_process: RegGetValue Error: %d\n", retval);
    //    return retval;
    //}

    // Create Attribute List
    STARTUPINFOEXW StartupInfoEx = { 0 };
    SIZE_T AttributeListSize = 0;
    StartupInfoEx.StartupInfo.cb = sizeof(StartupInfoEx);
    InitializeProcThreadAttributeList(NULL, 1, 0, &AttributeListSize);
    if (AttributeListSize == 0) {
        retval = GetLastError();
        wprintf(L"[PPL_RUNNER] start_child_process: InitializeProcThreadAttributeList1 Error: %d\n", retval);
        return retval;
    }
    StartupInfoEx.lpAttributeList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, AttributeListSize);
    if (InitializeProcThreadAttributeList(StartupInfoEx.lpAttributeList, 1, 0, &AttributeListSize) == FALSE) {
        retval = GetLastError();
        wprintf(L"[PPL_RUNNER] start_child_process: InitializeProcThreadAttributeList2 Error: %d\n", retval);
        return retval;
    }

    // Set ProtectionLevel to be the same, i.e. PPL
    DWORD ProtectionLevel = PROTECTION_LEVEL_SAME;
    if (UpdateProcThreadAttribute(StartupInfoEx.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
        &ProtectionLevel,
        sizeof(ProtectionLevel),
        NULL,
        NULL) == FALSE)
    {
        retval = GetLastError();
        wprintf(L"[PPL_RUNNER] start_child_process: UpdateProcThreadAttribute Error: %d\n", retval);
        return retval;
    }

    // Start Process (hopefully)
    PROCESS_INFORMATION ProcessInformation = { 0 };
    wprintf(L"[PPL_RUNNER] start_child_process: Creating Process2: '%s'\n", childCMD);
    if (CreateProcess(NULL,
        childCMD,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
        NULL,
        NULL,
        (LPSTARTUPINFOW)&StartupInfoEx,
        &ProcessInformation) == FALSE)
    {
        retval = GetLastError();
        if (retval == ERROR_INVALID_IMAGE_HASH) {
            wprintf(L"[PPL_RUNNER] start_child_process: CreateProcess Error: Invalid Certificate\n");
        }
        else {
            wprintf(L"[PPL_RUNNER] start_child_process: CreateProcess Error: %d\n", retval);
        }
        return retval;
    }
    // Don't wait on process handle, we're setting our child free into the wild
    // This is to prevent any possible deadlocks

    wprintf(L"[PPL_RUNNER] start_child_process finished");
    return retval;
}

void omfg() {
    wchar_t buffer[512] = L"start:notepad.exe";

    if (wcsstr(buffer, L"start:") != NULL) {
        wchar_t* token = NULL, * context = NULL;
        wprintf(L"Control: Received command: start");

        // should give "start:"
        token = wcstok_s(buffer, L":", &context);
        if (token != NULL) {
            // should give the thing after "start:"
            token = wcstok_s(NULL, L":", &context);
            if (token != NULL) {
                wprintf(L"Control: Target: %s", token);
            }
        }
    }
}


void PrintStackTrace() {
    // Initialize the symbol handler for the current process
    HANDLE process = GetCurrentProcess();
    SymInitialize(process, NULL, TRUE);

    // Capture stack trace
    void* stack[64];
    unsigned short frames = CaptureStackBackTrace(0, 64, stack, NULL);

    // Allocate memory for symbol information
    SYMBOL_INFO* symbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char), 1);
    if (symbol == NULL) {
        return;
    }
    symbol->MaxNameLen = 255;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

    // Print each frame of the stack trace
    for (unsigned short i = 0; i < frames; i++) {
        DWORD64 address = (DWORD64)(stack[i]);

        // Get symbol information for the current stack address
        if (SymFromAddr(process, address, 0, symbol)) {
            printf("Frame %d: %s - 0x%0X\n", i, symbol->Name, (unsigned int)symbol->Address);
        }
        else {
            printf("Frame %d: Error getting symbol info (error code: %lu)\n", i, GetLastError());
        }
    }

    // Cleanup
    free(symbol);
    SymCleanup(process);
}

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

void LogMyStackTrace2(wchar_t* buf, size_t buf_size) {
    CONTEXT context;
    STACKFRAME64 stackFrame;
    DWORD machineType;
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();

    // Capture the context of the current thread
    RtlCaptureContext(&context);

    // Initialize DbgHelp for symbol resolution
    //SymInitialize(hProcess, NULL, TRUE);

    ZeroMemory(&stackFrame, sizeof(STACKFRAME64));

    // x64 (64-bit) architecture
    machineType = IMAGE_FILE_MACHINE_AMD64;
    stackFrame.AddrPC.Offset = context.Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context.Rsp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = context.Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;

    MEMORY_BASIC_INFORMATION mbi;
    size_t written = 0;
    int n = 0;
    SIZE_T returnLength = 0;
    while (StackWalk64(machineType, hProcess, hThread, &stackFrame, &context,
        NULL, NULL, NULL, NULL))
    {
        if (n > MAX_CALLSTACK_ENTRIES) {
            // dont go too deep
            break;
        }
        if (buf_size > DATA_BUFFER_SIZE) {
            // as buf_size is size_t, it will underflow when too much callstack is appended
            LOG_A(LOG_WARNING, "StackWalk: Not enough space for whole stack, stopped at %i", n);
            break;
        }
        DWORD64 address = stackFrame.AddrPC.Offset;

        /*if (NtQueryVirtualMemory(hProcess, (PVOID)address, MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength) != 0) {
            written = swprintf_s(buf, WCHAR_BUFFER_SIZE, L"idx:%i;backtrace:%p;page_addr:invalid;size:invalid;state:invalid;protect:invalid;type:invalid",
                n, address);
        }
        buf_size -= written;
        buf += written;
        printf("Left: %d\n", buf_size);
        */
        // Resolve the symbol at this address
        /*char symbolBuffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)symbolBuffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        if (SymFromAddr(hProcess, address, 0, pSymbol))
        {
            printf("  %s - 0x%0llX\n", pSymbol->Name, pSymbol->Address);
        }
        else
        {
            printf("  [Unknown symbol] - 0x%0llX\n", address);
        }*/

        n += 1;
    }

    // Cleanup after stack walk
    //SymCleanup(hProcess);

    return;
}

void teststr() {
    LARGE_INTEGER time = { 0 };
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
        L"type:dll;time:%llu;krn_pid:%llu;func:NtCreateTimer2;attributes:0x%lx;desired_access:0x%x;",
        time.QuadPart, (unsigned __int64)GetCurrentProcessId(), 0x444, 0x123);

    size_t len = wcslen(buf);
    //AddMyStackTrace(buf + len, DATA_BUFFER_SIZE - len);
    LogMyStackTrace2(buf + len, DATA_BUFFER_SIZE - len);

    wprintf(L"Done: %s\n", buf);
}



// Helper
DWORD FindProcessId(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, processName.c_str())) {
                processId = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return processId;
}


void test_cache_procinfo() {
    g_config.targetExeName = L"notepad.exe";

    DWORD pid = FindProcessId(std::wstring(g_config.targetExeName));
    g_ProcessCache.getObject(pid);

}


int DetectionTest() {
    std::string json_file_content = read_file("Data\\notepad.json");
    if (json_file_content.empty()) {
        return 1; // Exit if the file could not be read
    }

    nlohmann::json json_data;
    try {
        json_data = nlohmann::json::parse(json_file_content);
    }
    catch (const std::exception& e) {
        std::cerr << "Failed to parse JSON: " << e.what() << std::endl;
        return 1;
    }

    if (!json_data.is_array()) {
        std::cerr << "JSON data is not an array." << std::endl;
        return 1;
    }
    for (const auto& event : json_data) {
        AnalyzeEventJson(event);
    }

}


int wmain(int argc, wchar_t* argv[]) {


    if (argc != 3) {
        printf("Usage: rededrtester.exe <id> <pid>");
        return 1;
    }
    LOG_A(LOG_INFO, "RedTester");

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
    { // WTF
        /*printf("Query process information\n");
        Process* process = MakeProcess(pid);
        if (process != NULL) {
            process->display();

            std::wstring o = format_wstring2(L"type:peb;time:%lld;id:%lld;parent_pid:%lld;image_path:%ls;commandline:%ls;working_dir:%ls;is_debugged:%d;is_protected_process:%d;is_protected_process_light:%d;image_base:0x%p",
                0,
                process->id,
                process->parent_pid,
                process->image_path.c_str(),
                process->commandline.c_str(),
                process->working_dir.c_str(),
                process->is_debugged,
                process->is_protected_process,
                process->is_protected_process_light,
                process->image_base
            );
            do_output(o);
        }*/
    }
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
    {
        char timeString[100];
        LARGE_INTEGER largeInt;
        largeInt = get_time2();
        printf("Time: %lld\n", largeInt.QuadPart);
        ConvertLargeIntegerToReadableString2(largeInt, timeString, sizeof(timeString));
        printf("Readable Time: %s\n", timeString);
    }
    break;
    case 9:
    {
        std::wstring input = L"type:dll;time:28500;krn_pid:133695059491286994;func:AllocateVirtualMemory;pid:FFFFFFFFFFFFFFFF;addr:0000004F821FCB60;zero:0x7fffffff;size:42;type:0x1000:protect:0x4";
        std::wstring json = ConvertToJSON2(input);
        std::wcout << L"JSON Output: " << json << std::endl;
    }
    break;
    case 10:
        omfg();
        break;
    case 11:
    {
        WCHAR childCMD[MAX_BUF_SIZE];
        wcscpy_s(childCMD, MAX_BUF_SIZE, L"C:\\windows\\system32\\cmd.exe /c \"echo AAA > c:\\rededr\\aa\"");
        start_child_process((wchar_t*)childCMD);
        break;
    }
    case 12:
        FakePplPipeClient();
        break;
    case 13:
        //LogMyStackTrace();
        //PrintStackTrace2();
        break;
    case 14:
        teststr();
        test_cache_procinfo();
        break;
    case 15:
        DetectionTest();
    }



}
