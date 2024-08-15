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
        MessageBox(NULL, L"Error", L"SendDllPipe: Error when sending to pipe", MB_OK);
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
        MessageBox(NULL, L"ERR1", L"ERR1", MB_OK);
        return 1;
    }
    return 0;
}

//----------------------------------------------------


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
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    int ret = swprintf_s(buf, DATA_BUFFER_SIZE, L"AllocateVirtualMemory:%p:%p:%#lx:%llu:%#lx:%#lx",
        ProcessHandle, BaseAddress, ZeroBits, *RegionSize, AllocationType, Protect);
    SendDllPipe(buf);

    // jump on the originate NtAllocateVirtualMemory
    return pOriginalNtAllocateVirtualMemory(GetCurrentProcess(), BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}


DWORD WINAPI InitPipeThread(LPVOID param) {
    InitDllPipe();
    return 0;
}

// This function initializes the hooks via the MinHook library
DWORD WINAPI InitHooksThread(LPVOID param) {
    if (MH_Initialize() != MH_OK) {
        return -1;
    }

    InitDllPipe();

    // Here we specify which function from wich DLL we want to hook
    MH_CreateHookApi(
        L"ntdll",                                     // Name of the DLL containing the function to  hook
        "NtAllocateVirtualMemory",                    // Name of the function to hook
        NtAllocateVirtualMemory,                      // Address of the function on which to jump when hooking 
        (LPVOID*)(&pOriginalNtAllocateVirtualMemory) // Address of the original NtAllocateVirtualMemory function
    );

    // Enable the hook on NtAllocateVirtualMemory
    MH_STATUS status = MH_EnableHook(MH_ALL_HOOKS);
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