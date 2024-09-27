#include "pch.h"
#include <stdio.h>

#include "dllhelper.h"
#include "../Shared/common.h"
#include <winternl.h>  // needs to be on bottom?
#include <dbghelp.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")

typedef struct __Config {
    BOOL do_stacktrace = true;
} config;

config Config;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;


typedef NTSTATUS(NTAPI* pNtQueryVirtualMemory)(
    HANDLE                   ProcessHandle,
    PVOID                    BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID                    MemoryInformation,
    SIZE_T                   MemoryInformationLength,
    PSIZE_T                  ReturnLength
    );

pNtQueryVirtualMemory NtQueryVirtualMemory = nullptr;


VOID log_message(const wchar_t* format, ...)
{
    WCHAR message[MAX_BUF_SIZE] = L"[DLL] ";
    DWORD offset = wcslen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = _vsnwprintf_s(&message[offset], MAX_BUF_SIZE - offset, MAX_BUF_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    OutputDebugString(message);
}


void UnicodeStringToWChar(const UNICODE_STRING* ustr, wchar_t* dest, size_t destSize)
{
    if (!ustr || !dest || destSize == 0) {
        return;  // Invalid arguments or destination size is zero
    }

    // Ensure that the source UNICODE_STRING is valid
    if (ustr->Length == 0 || ustr->Buffer == NULL) {
        dest[0] = L'\0';  // Set dest to an empty string
        return;
    }

    // Get the number of characters to copy (Length is in bytes, so divide by sizeof(WCHAR))
    size_t numChars = ustr->Length / sizeof(WCHAR);

    // Copy length should be the smaller of the available characters or the destination size minus 1 (for null terminator)
    size_t copyLength = (numChars < destSize - 1) ? numChars : destSize - 1;

    // Use wcsncpy_s to safely copy the string
    wcsncpy_s(dest, destSize, ustr->Buffer, copyLength);

    // Ensure the destination string is null-terminated
    dest[copyLength] = L'\0';
}

//----------------------------------------------------

HANDLE hPipe = NULL;

void sendDllPipeCallstack(wchar_t* buffer) {
    if (Config.do_stacktrace) {
        SendDllPipe(buffer);
    }
}

void SendDllPipe(wchar_t* buffer) {
    DWORD pipeBytesWritten = 0;
    DWORD res = 0;

    if (hPipe == NULL) {
        log_message(L"Pipe closed");
        return;
    }
    DWORD len = (DWORD)(wcslen(buffer) * 2) + 2; // +2 -> include two trailing 0 bytes
    res = WriteFile(hPipe, buffer, len, &pipeBytesWritten, NULL);
    if (res == FALSE) {
        log_message(L"Error when sending to pipe: %d", GetLastError());
    }
}


void InitDllPipe() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        NtQueryVirtualMemory = (pNtQueryVirtualMemory)GetProcAddress(hNtdll, "NtQueryVirtualMemory");
    }

    hPipe = CreateFile(DLL_PIPE_NAME, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        log_message(L"Could not open pipe");
    }

    // Retrieve config (first packet)
    // this is the only read for this pipe
    char buffer[256];
    DWORD bytesRead;
    if (!ReadFile(hPipe, &buffer, 256, &bytesRead, NULL)) {
        log_message(L"Could not read first message from pipe from RedEdr.exe: %lu. Abort.", 
            GetLastError());
        return;
    }
    if (strstr(buffer, "callstack:1")) {
        Config.do_stacktrace = true;
        log_message(L"Callstack: Enabled");
    }
    else {
        log_message(L"Callstack: Disabled");
    }
}


LARGE_INTEGER get_time() {
    FILETIME fileTime;
    LARGE_INTEGER largeInt;

    // Get the current system time as FILETIME
    GetSystemTimeAsFileTime(&fileTime);

    // Convert FILETIME to LARGE_INTEGER
    largeInt.LowPart = fileTime.dwLowDateTime;
    largeInt.HighPart = fileTime.dwHighDateTime;

    return largeInt;
}


/*************** Procinfo stuff ******************/

// LOG's the stacktrace of THIS function
void LogMyStackTrace() {
    CONTEXT context;
    STACKFRAME64 stackFrame;
    DWORD machineType;
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();
    wchar_t buf[DATA_BUFFER_SIZE] = { 0 };

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
        if (n > 5) {
            break;
        }
        DWORD64 address = stackFrame.AddrPC.Offset;

        if (NtQueryVirtualMemory(hProcess, (PVOID) address, MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength) != 0) {
            written = swprintf_s(buf, DATA_BUFFER_SIZE, L"idx:%i;backtrace:%p;page_addr:invalid;size:invalid;state:invalid;protect:invalid;type:invalid",
                n, address);
        }
        else {
            written = swprintf_s(buf, DATA_BUFFER_SIZE, L"idx:%i;backtrace:%p;page_addr:%p;size:%zu;state:0x%lx;protect:0x%lx;type:0x%lx",
                n, address, mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type);
        }
        SendDllPipe(buf);

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
