#include <stdio.h>

#include "pch.h"
#include "minhook/include/MinHook.h"
#include "../Shared/common.h"


//----------------------------------------------------

HANDLE hPipe = NULL;

void SendDllPipe(wchar_t* buffer) {
    DWORD pipeBytesWritten = 0;
    DWORD res = 0;

    if (hPipe == NULL) {
        return;
    }
    DWORD len = (wcslen(buffer) * 2) + 2; // +2 -> include two trailing 0 bytes
    res = WriteFile(
        hPipe,
        buffer,
        len,
        &pipeBytesWritten,
        NULL
    );
    if (res == FALSE) {
        MessageBox(NULL, L"SendDllPipe: Error when sending to pipe", L"RedEdr Injected DLL error", MB_OK);
    }
}


int InitDllPipe() {
    hPipe = CreateFile(
        DLL_PIPE_NAME,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        //        printf("Error connecting to named pipe: %ld", GetLastError());
        MessageBox(NULL, L"Could not open pipe", L"RedEdr Injected DLL error", MB_OK);
        return 1;
    }
    return 0;
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

//----------------------------------------------------


/******************* AllocateVirtualMemory ************************/


// Defines the prototype of the NtAllocateVirtualMemoryFunction
typedef DWORD(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

// Pointer to the trampoline function used to call the original NtAllocateVirtualMemory
pNtAllocateVirtualMemory pOriginalNtAllocateVirtualMemory = NULL;
DWORD NTAPI NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    int ret = swprintf_s(buf, DATA_BUFFER_SIZE, L"type:dll;time:%llu;krn_pid:%llu;func:AllocateVirtualMemory;pid:%p;base_addr:%p;zero:%#lx;size:%llu;type:%#lx;protect:%#lx",
        time, (unsigned __int64) GetCurrentProcessId(), ProcessHandle, BaseAddress, ZeroBits, *RegionSize, AllocationType, Protect);
    SendDllPipe(buf);

    // jump on the originate NtAllocateVirtualMemory
    return pOriginalNtAllocateVirtualMemory(GetCurrentProcess(), BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}


/******************* ProtectVirtualMemory ************************/


wchar_t* GetMemoryPermissions(wchar_t* buf, DWORD protection) {
    //char permissions[4] = "---"; // Initialize as "---"
    wcscpy_s(buf, 16, L"---");

    if (protection & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[0] = L'R'; // Readable
    }
    if (protection & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[1] = L'W'; // Writable
    }
    if (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[2] = L'X'; // Executable
    }
    buf[3] = L'\x00';

    return buf;
}

// Defines the prototype of the NtProtectVirtualMemoryFunction
typedef DWORD(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PULONG NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
    );
pNtProtectVirtualMemory pOriginalNtProtectVirtualMemory = NULL;
DWORD NTAPI NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PULONG NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    
    wchar_t mem_perm[16] = L"";
    memset(mem_perm, 0, sizeof(mem_perm));
    GetMemoryPermissions(mem_perm, NewAccessProtection);
    
    int ret = swprintf_s(buf, DATA_BUFFER_SIZE, 
        L"type:dll;time:%llu;krn_pid:%llu;func:ProtectVirtualMemory;pid:%p;base_addr:%p;size:%llu;new_access:%#lx;new_access_str:%ls;old_access:%#lx",
        time, (unsigned __int64)GetCurrentProcessId(), ProcessHandle, 
        BaseAddress, NumberOfBytesToProtect, NewAccessProtection, mem_perm, OldAccessProtection);
    SendDllPipe(buf);

    // jump on the originate NtProtectVirtualMemory
    return pOriginalNtProtectVirtualMemory(GetCurrentProcess(), BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}


/******************* MapViewOfSection ************************/

// Defines the prototype of the NtMapViewOfSectionFunction
typedef DWORD(NTAPI* pNtMapViewOfSection)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    DWORD           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Protect
    );
pNtMapViewOfSection pOriginalNtMapViewOfSection = NULL;
DWORD NTAPI NtMapViewOfSection(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    DWORD           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Protect
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    wchar_t mem_perm[16] = L"";
    memset(mem_perm, 0, sizeof(mem_perm));
    GetMemoryPermissions(mem_perm, Protect);

    int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
        L"type:dll;time:%llu;krn_pid:%llu;func:MapViewOfSection;section_handle:0x%p;process_handle:0x%p;base_address:0x%p;zero_bits:%llu;size:%llu;section_offset:%lld;view_size:%llu;inherit_disposition:%x;alloc_type:%x;protect:%x;protect_str:%ls;",
        time, (unsigned __int64)GetCurrentProcessId(),
        SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
    SendDllPipe(buf);

    // jump on the originate NtMapViewOfSection
    return pOriginalNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
}


/******************* WriteVirtualMemory ************************/

// Defines the prototype of the NtWriteVirtualMemoryFunction
typedef DWORD(NTAPI* pNtWriteVirtualMemory)(
    HANDLE              ProcessHandle,
    PVOID               BaseAddress,
    PVOID               Buffer,
    ULONG               NumberOfBytesToWrite,
    PULONG              NumberOfBytesWritten
);
pNtWriteVirtualMemory pOriginalNtWriteVirtualMemory = NULL;
DWORD NTAPI NtWriteVirtualMemory(
    HANDLE              ProcessHandle,
    PVOID               BaseAddress,
    PVOID               Buffer,
    ULONG               NumberOfBytesToWrite,
    PULONG              NumberOfBytesWritten
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
        L"type:dll;time:%llu;krn_pid:%llu;func:WriteVirtualMemory;process_handle:0x%p;base_address:0x%p;buffer:0x%p;size:%llu",
        time, (unsigned __int64)GetCurrentProcessId(),
        ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite);
    SendDllPipe(buf);

    // jump on the originate NtWriteVirtualMemory
    return pOriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

/******************* NtSetContextThread ************************/

// Defines the prototype of the NtSetContextThreadFunction
typedef DWORD(NTAPI* pNtSetContextThread)(
    IN HANDLE               ThreadHandle,
    IN PCONTEXT             Context
    );
pNtSetContextThread pOriginalNtSetContextThread = NULL;
DWORD NTAPI NtSetContextThread(
    IN HANDLE               ThreadHandle,
    IN PCONTEXT             Context
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
        L"type:dll;time:%llu;krn_pid:%llu;func:SetContextThread;thread_handle:0x%p;",
        time, (unsigned __int64)GetCurrentProcessId(), ThreadHandle);
    SendDllPipe(buf);

    // jump on the originate NtSetContextThread
    return pOriginalNtSetContextThread(ThreadHandle, Context);
}


//----------------------------------------------------


// This function initializes the hooks via the MinHook library
DWORD WINAPI InitHooksThread(LPVOID param) {
    if (MH_Initialize() != MH_OK) {
        return -1;
    }
    MH_STATUS status;

    InitDllPipe();

    /*
    +VirtualAlloc, +VirtualProtect
    +MapViewOfFile, /MapViewOfFile2
    /VirtualAllocEx, /VirtualProtectEx
    QueueUserAPC
    SetThreadContext
    +WriteProcessMemory, ReadProcessMemory

    +NtMapViewOfSection  NtUnmapViewOfSection  NtUnmapViewOfSectionEx
    */

    MH_CreateHookApi(
        L"ntdll",                                     // Name of the DLL containing the function to  hook
        "NtAllocateVirtualMemory",                    // Name of the function to hook
        NtAllocateVirtualMemory,                      // Address of the function on which to jump when hooking 
        (LPVOID*)(&pOriginalNtAllocateVirtualMemory) // Address of the original NtAllocateVirtualMemory function
    );
    MH_CreateHookApi(
        L"ntdll",
        "NtProtectVirtualMemory",
        NtProtectVirtualMemory,
        (LPVOID*)(&pOriginalNtProtectVirtualMemory)
    );
    MH_CreateHookApi(
        L"ntdll",
        "NtMapViewOfSection",
        NtMapViewOfSection,
        (LPVOID*)(&pOriginalNtMapViewOfSection)
    );
    MH_CreateHookApi(
        L"ntdll",
        "NtWriteVirtualMemory",
        NtWriteVirtualMemory,
        (LPVOID*)(&pOriginalNtWriteVirtualMemory)
    );
    MH_CreateHookApi(
        L"ntdll",
        "NtSetContextThread",
        NtSetContextThread,
        (LPVOID*)(&pOriginalNtSetContextThread)
    );

    status = MH_EnableHook(MH_ALL_HOOKS);

    return status;
}


// Here is the DllMain of our DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        // This DLL will not be loaded by any thread so we simply disable DLL_TRHEAD_ATTACH and DLL_THREAD_DETACH
        DisableThreadLibraryCalls(hModule);

        // Calling WinAPI32 functions from the DllMain is a very bad practice 
        // since it can basically lock the program loading the DLL
        // Microsoft recommends not using any functions here except a few one like 
        // CreateThread IF AND ONLY IF there is no need for synchronization
        // So basically we are creating a thread that will execute the InitHooksThread function 
        // thus allowing us hooking the NtAllocateVirtualMemory function
        HANDLE hThread = CreateThread(NULL, 0, InitHooksThread, NULL, 0, NULL);
        if (hThread != NULL) {
            CloseHandle(hThread);
        }
        /*hThread = CreateThread(NULL, 0, InitPipeThread, NULL, 0, NULL);
        if (hThread != NULL) {
            CloseHandle(hThread);
        }*/
        break;
    }
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}