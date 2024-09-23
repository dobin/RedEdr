#include "pch.h"
#include <stdio.h>

#include "dllhelper.h"
#include "../Shared/common.h"
#include <winternl.h>  // needs to be on bottom?


typedef struct __Config {
    BOOL do_stacktrace = true;
} config;

config Config;


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
        return;
    }
    DWORD len = (DWORD)(wcslen(buffer) * 2) + 2; // +2 -> include two trailing 0 bytes
    res = WriteFile(
        hPipe,
        buffer,
        len,
        &pipeBytesWritten,
        NULL
    );
    if (res == FALSE) {
        log_message(L"Error when sending to pipe: %d", GetLastError());
    }
}


void InitDllPipe() {
    hPipe = CreateFile(DLL_PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        log_message(L"Could not open pipe");
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


/***/
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


BOOL GetStackTraceLogFor(HANDLE hProcess, PVOID address, int idx, wchar_t *buf, size_t buf_len) {
    SIZE_T returnLength = 0;
    MEMORY_BASIC_INFORMATION mbi;

    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (hNtDll == NULL) {
        log_message(L"Procinfo: could not find ntdll.dll");
        return FALSE;
    }
    if (NtQueryVirtualMemory(hProcess, address, MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength) != 0) {
        swprintf_s(buf, buf_len, L"backtrace:%p;page_addr:%p;idx:%i;size:invalid;state:invalid;protect:invalid;type:invalid",
            address, mbi.BaseAddress, idx);
        return TRUE;

        return FALSE;
    }
    else {
        swprintf_s(buf, buf_len, L"backtrace:%p;page_addr:%p;idx:%i;size:%zu;state:0x%lx;protect:0x%lx;type:0x%lx",
            address, mbi.BaseAddress, idx, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type);
        return TRUE;
    }
}


// LOG's the stacktrace of THIS function
void LogMyStackTrace() {
    void* stack[64];
    unsigned short frames = CaptureStackBackTrace(0, 64, stack, NULL);

    if (NtQueryVirtualMemory == NULL) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            NtQueryVirtualMemory = (pNtQueryVirtualMemory)GetProcAddress(hNtdll, "NtQueryVirtualMemory");
        }
        else {
            log_message(L"Stacktrace error");
        }
    }

    /* It would look like this:
        Frame 0: LogMyStackTrace - 0xF4A1AC60           skip
        Frame 1: wmain - 0xF4A1C170
        Frame 2: invoke_main - 0xF4A2FFE0
        Frame 3: __scrt_common_main_seh - 0xF4A2FD90    skip
        Frame 4: __scrt_common_main - 0xF4A2FD70        skip
        Frame 5: wmainCRTStartup - 0xF4A300A0           skip
        Frame 6: BaseThreadInitThunk - 0x3B672560       skip
        Frame 7: RtlUserThreadStart - 0x3CF2AF00        skip

        but with MAX_CALLSTACK_ENTRIES unskipped, starting from 1
    */

    unsigned short start = 0;
    unsigned short end = frames;
    if (frames > 6) {
        start = 1;
        end = frames - 5;
    }
    if (frames > (6 + MAX_CALLSTACK_ENTRIES)) {
        end = start + MAX_CALLSTACK_ENTRIES;
    }

    HANDLE hProcess = GetCurrentProcess();
    int n = 0;
    wchar_t buf[1024];
    for (unsigned short i = start; i < end; i++) {
        BOOL ret = GetStackTraceLogFor(hProcess, stack[i], i, buf, 1024);
        if (ret) {
            //log_message(buf);
            SendDllPipe(buf);
        }
    }
}
