#include <stdio.h>
#include <windows.h>

#include "dllinjector.h"
#include "logging.h"
#include "config.h"


// File mostly from MyDumbEdr


BOOL remote_inject(DWORD target_pid) {
    char dll_full_path[MAX_PATH];
    strcpy_s(dll_full_path, g_config.inject_dll_path);

    LOG_A(LOG_INFO, "DLL Inject into process %d (%s)", target_pid, dll_full_path);

    // Opening the process with necessary privileges 
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, target_pid);
    if (hProcess == NULL) {
        LOG_A(LOG_ERROR, "Can't open handle, error: % lu", GetLastError());
        return FALSE;
    }
    //printf("\tOpen handle on PID: %d\n", target_pid);

    // Looking for the LoadLibraryA function in the kernel32.dll
    FARPROC loadLibAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (loadLibAddress == NULL) {
        LOG_A(LOG_ERROR, "Could not find LoadLibraryA, error: %lu", GetLastError());
        return FALSE;
    }
    //printf("\tFound LoadLibraryA function\n");

    // Allocating some RWX memory
    LPVOID vae_buffer;
    vae_buffer = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (vae_buffer == NULL) {
        LOG_A(LOG_ERROR, "Can't allocate memory, error: %lu", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    //printf("\tAllocated: %d bytes\n", MAX_PATH);

    // Writing the path of the DLL to inject
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, vae_buffer, dll_full_path, MAX_PATH, &bytesWritten)) {
        LOG_A(LOG_ERROR, "Can't write into memory, error: %lu", GetLastError());
        VirtualFreeEx(hProcess, vae_buffer, MESSAGE_SIZE, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    //printf("\tWrote %zu in %d process memory\n", bytesWritten, target_pid);

    // Creating a thread that will call LoadLibraryA and the path of the MyDUMBEDRDLL to load as argument
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddress, vae_buffer, 0, NULL);
    if (hThread == NULL) {
        LOG_A(LOG_ERROR, "Can't launch remote thread, error: %lu", GetLastError());
        VirtualFreeEx(hProcess, vae_buffer, MESSAGE_SIZE, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    LOG_A(LOG_INFO, "    Looks like success");

    VirtualFreeEx(hProcess, vae_buffer, MESSAGE_SIZE, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}
