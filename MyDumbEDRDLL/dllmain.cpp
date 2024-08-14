#include <stdio.h>


#include "pch.h"
#include "minhook/include/MinHook.h"


//----------------------------------------------------

HANDLE hPipe = NULL;


void WriteToServerPipe(char* buffer, int buffer_size) {
    DWORD pipeBytesWritten = 0;
    DWORD res = 0;

    if (hPipe == NULL) {
        return;
    }

    //MessageBox(NULL, L"Send", L"Send", MB_OK);

    res = WriteFile(
        hPipe,       // Handle to the named pipe
        buffer,          // Buffer to write from
        buffer_size,      // Size of the buffer 
        &pipeBytesWritten, // Numbers of bytes written
        NULL               // Whether or not the pipe supports overlapped operations
    );
    if (res == FALSE) {
        MessageBox(NULL, L"ERR2", L"ERR2", MB_OK);

    }
}

#define BUFFER_SIZE 1024
int ConnectToServerPipe() {
    //char buffer[BUFFER_SIZE] = "Hello from dll";
    const wchar_t* pipeName = L"\\\\.\\pipe\\RedEdrDllCom";

    // Connect to the named pipe
    hPipe = CreateFile(
        pipeName,              // Pipe name
        GENERIC_WRITE,          // Write access
        0,                      // No sharing
        NULL,                   // Default security attributes
        OPEN_EXISTING,          // Opens existing pipe
        0,                      // Default attributes
        NULL);                  // No template file

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
    char buf[BUFFER_SIZE] = "Test 12 12";
    sprintf_s(buf, "AllocateVirtualMemory:%p:%p:%#lx:%llu:%#lx:%#lx",
        ProcessHandle, BaseAddress, ZeroBits, *RegionSize, AllocationType, Protect);
    WriteToServerPipe(buf, BUFFER_SIZE);

    // Checks if the program is trying to allocate some memory and protect it with RWX 
    if (Protect == PAGE_EXECUTE_READWRITE) {
        // If yes, we notify the user and terminate the process
        MessageBox(NULL, L"Dude, are you trying to RWX me ?", L"Found u bro", MB_OK);
        TerminateProcess(GetCurrentProcess(), 0xdeadb33f);
    }
    else {
        //MessageBox(NULL, L"Alloc", L"Found u bro", MB_OK);
    }

    //If no, we jump on the originate NtAllocateVirtualMemory
    return pOriginalNtAllocateVirtualMemory(GetCurrentProcess(), BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}


DWORD WINAPI InitPipeThread(LPVOID param) {
    ConnectToServerPipe();
    return 0;
}

// This function initializes the hooks via the MinHook library
DWORD WINAPI InitHooksThread(LPVOID param) {
    if (MH_Initialize() != MH_OK) {
        return -1;
    }

    ConnectToServerPipe();

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