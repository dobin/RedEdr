#include "dllhelper.h"
#include "../Shared/common.h"
#include <winternl.h>  // needs to be on bottom?
#include <dbghelp.h>
#include <stdio.h>
#include <thread>
#include <mutex>

#include "piping.h"
#include "logging.h"
#include "utils.h"
#include "process_query.h"

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


//----------------------------------------------------
// Pipe stuff

// Pipe Init
void InitDllPipe() {
    if (!pipeClient.Connect(DLL_PIPE_NAME)) {
        LOG_W(LOG_ERROR, L"Could not connect to RedEdr.exe at %s", DLL_PIPE_NAME);
        return;
    }

    // Retrieve config (first packet)
    //   this is the only time we read from this pipe
    LOG_A(LOG_INFO, "Waiting for config...");
    wchar_t buffer[WCHAR_BUFFER_SIZE];
    if (pipeClient.Receive(buffer, WCHAR_BUFFER_SIZE)) {
        if (wcsstr(buffer, L"callstack:1") != NULL) {
            Config.do_stacktrace = true;
            LOG_W(LOG_INFO, L"Config: Callstack Enabled");
        }
        else {
            Config.do_stacktrace = false;
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

std::mutex InitSymMtx;

void doInitSym(HANDLE hProcess) {
    // First thread gonna do the shit. 
    // All others gonna wait.
    std::lock_guard<std::mutex> lock(InitSymMtx);
    
    // Dont record all the stuff SymInitialize()
    // is doing (disable hooking output)
    HooksInitialized = FALSE;

    SymInitialize(hProcess, NULL, TRUE);

    // Re-enable hooking output
    HooksInitialized = TRUE;
}


size_t LogMyStackTrace(wchar_t* buf, size_t buf_size) {
    CONTEXT context;
    STACKFRAME64 stackFrame;
    DWORD machineType;
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();
    size_t written = 0;

    if (!IsSymInitialized) {
        doInitSym(hProcess);
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
    wchar_t* begin_str = (wchar_t *) L"\"callstack\":[";
    int l = wcscat_s(buf, buf_size, begin_str);
    buf_size -= wcslen(begin_str);
    buf += wcslen(begin_str);
    written += wcslen(begin_str);

    MEMORY_BASIC_INFORMATION mbi;
    int n = 0;
    SIZE_T returnLength = 0;
    int didWalk = 0;
    while (StackWalk64(machineType, hProcess, hThread, &stackFrame, &context,
        NULL, NULL, NULL, NULL))
    {
        DWORD64 address = stackFrame.AddrPC.Offset;
        size_t w = 0;
        didWalk = 1;

        if (n > MAX_CALLSTACK_ENTRIES) {
            // dont go too deep
            break;
        }
        if (buf_size > DATA_BUFFER_SIZE - 2) { // -2 for ending ]
            // as buf_size is size_t, it will underflow when too much callstack is appended
            LOG_A(LOG_WARNING, "StackWalk: Not enough space for whole stack, stopped at %i", n);
            break;
        }

        ProcessAddrInfoRet processAddrInfoRet = ProcessAddrInfo(hProcess, address);
        w = swprintf_s(buf, WCHAR_BUFFER_SIZE, L"{\"idx\":%i,\"addr\":%llu,\"page_addr\":%llu,\"size\":%zu,\"state\":%lu,\"protect\":\"%s\",\"type\":\"%s\"},",
            n, 
            address, 
            processAddrInfoRet.base_addr,
            processAddrInfoRet.region_size, 
            processAddrInfoRet.stateStr.c_str(),
            processAddrInfoRet.protectStr.c_str(),
            processAddrInfoRet.typeStr.c_str());
        if (w == 0) {
            LOG_A(LOG_ERROR, "Error");
        }
        buf_size -= w;
        buf += w;
        written += w;

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

    // remove last comma if we added at least one entry
    if (didWalk) {
        buf[wcslen(buf) - 1] = L']';
        buf[wcslen(buf) - 0] = L'\x00';
    }
    else {
        wcscat_s(buf, buf_size, L"]");
        written += 1;
    }

    // We should have space...
    //l = wcscat_s(buf, buf_size, L"]");
    //written += 1;

    // Cleanup after stack walk
    //SymCleanup(hProcess);

    return written;
}

