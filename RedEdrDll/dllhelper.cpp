#include "dllhelper.h"
#include "../Shared/common.h"
#include <winternl.h>  // needs to be on bottom?
#include <dbghelp.h>
#include <stdio.h>
#include "piping.h"
#include "logging.h"
#include "utils.h"

#pragma comment(lib, "dbghelp.lib")

// Runtime config
// Taken from server on pipe connect
typedef struct __Config {
    BOOL do_stacktrace = true;
} config;

config Config;

// The pipe to RedEdr.exe
// Read first message as config,
// then send all the data
PipeClient pipeClient;

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


//----------------------------------------------------
// Pipe stuff

// Pipe Init
void InitDllPipe() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        NtQueryVirtualMemory = (pNtQueryVirtualMemory)GetProcAddress(hNtdll, "NtQueryVirtualMemory");
    }
    if (!pipeClient.Connect(DLL_PIPE_NAME)) {
        LOG_W(LOG_ERROR, L"Could not connect to RedEdr.exe at %s", DLL_PIPE_NAME);
        return;
    }

    // Retrieve config (first packet)
    //   this is the only time we read from this pipe
    LOG_A(LOG_INFO, "Waiting for config...");
    wchar_t buffer[WCHAR_SMALL_PIPE];
    if (pipeClient.Receive(buffer, WCHAR_SMALL_PIPE)) {
        if (wcsstr(buffer, L"callstack:1") != NULL) {
            Config.do_stacktrace = true;
            LOG_W(LOG_INFO, L"Config: Callstack Enabled");
        }
        else {
            LOG_W(LOG_INFO, L"Config: Callstack Disabled");
        }
    }
}


// Pipe send
void SendDllPipe(wchar_t* buffer) {
    pipeClient.Send(buffer);
}



/*************** Procinfo stuff ******************/

extern BOOL HooksInitialized;
BOOL IsSymInitialized = FALSE;

// Gives wrong answer (5)
void LogMyStackTrace(wchar_t* buf, size_t buf_size) {
    CONTEXT context;
    STACKFRAME64 stackFrame;
    DWORD machineType;
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();

    if (!IsSymInitialized) {
        // Dont record SymInitialize()
        HooksInitialized = FALSE;
        SymInitialize(hProcess, NULL, TRUE);
        HooksInitialized = TRUE;
        IsSymInitialized = TRUE;
    }

    RtlCaptureContext(&context);
    ZeroMemory(&stackFrame, sizeof(STACKFRAME64));
    machineType = IMAGE_FILE_MACHINE_AMD64;
    stackFrame.AddrPC.Offset = context.Rip;
    stackFrame.AddrFrame.Offset = context.Rbp;
    stackFrame.AddrStack.Offset = context.Rsp;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Mode = AddrModeFlat;

    // FUUUUU
    wchar_t* begin_str = (wchar_t *) L"callstack:[";
    int l = wcscat_s(buf, buf_size, begin_str);
    buf_size -= wcslen(begin_str);
    buf += wcslen(begin_str);

    MEMORY_BASIC_INFORMATION mbi;
    size_t written = 0;
    int n = 0;
    SIZE_T returnLength = 0;
    while (StackWalk64(machineType, hProcess, hThread, &stackFrame, &context,
        NULL, NULL, NULL, NULL))
    {
        DWORD64 address = stackFrame.AddrPC.Offset;

        if (n > MAX_CALLSTACK_ENTRIES) {
            // dont go too deep
            break;
        }
        if (buf_size > DATA_BUFFER_SIZE - 2) { // -2 for ending ]
            // as buf_size is size_t, it will underflow when too much callstack is appended
            LOG_A(LOG_WARNING, "StackWalk: Not enough space for whole stack, stopped at %i", n);
            break;
        }

        if (NtQueryVirtualMemory(hProcess, (PVOID)address, MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength) == 0) {
            written = swprintf_s(buf, WCHAR_BUFFER_SIZE, L"{idx:%i;addr:0x%I64x;page_addr:%p;size:%zu;state:0x%lx;protect:%s;type:%s},",
                n, address, mbi.BaseAddress, mbi.RegionSize, mbi.State, getMemoryRegionProtect(mbi.Protect), getMemoryRegionType(mbi.Type));
        }
        buf_size -= written;
        buf += written;

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

    // We should have space...
    l = wcscat_s(buf, buf_size, L"]");

    // Cleanup after stack walk
    //SymCleanup(hProcess);

    return;
}

