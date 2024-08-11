#include "pch.h"
#include "minhook/include/MinHook.h"


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

// This is the function that will be called whenever the injected process calls 
// NtAllocateVirtualMemory. This function takes the arguments Protect and checks
// if the requested protection is RWX (which shouldn't happen).
DWORD NTAPI NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {

    // Checks if the program is trying to allocate some memory and protect it with RWX 
    if (Protect == PAGE_EXECUTE_READWRITE) {
        // If yes, we notify the user and terminate the process
        MessageBox(NULL, L"Dude, are you trying to RWX me ?", L"Found u bro", MB_OK);
        TerminateProcess(GetCurrentProcess(), 0xdeadb33f);
    }
    else {
        MessageBox(NULL, L"Alloc", L"Found u bro", MB_OK);
    }

    //If no, we jump on the originate NtAllocateVirtualMemory
    return pOriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

// This function initializes the hooks via the MinHook library
DWORD WINAPI InitHooksThread(LPVOID param) {
    if (MH_Initialize() != MH_OK) {
        return -1;
    }

    MessageBox(NULL, L"INIT", L"Found u bro", MB_OK);

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
        break;
    }
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}