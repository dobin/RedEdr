#include <stdio.h>
#include <windows.h>

#include "dllinjector.h"
#include "loguru.hpp"
#include "config.h"


// File mostly from MyDumbEdr


BOOL remote_inject(DWORD target_pid) {
    char dll_full_path[MAX_PATH];

    //char dll_path[] = "x64\\Debug\\MyDumbEDRDLL.dll";
    //GetFullPathNameA(dll_path, MAX_PATH, dll_full_path, NULL);
    //strcpy_s(dll_full_path, "C:\\Users\\hacker\\source\\repos\\mydumbedr_orig\\x64\\Debug\\MyDumbEDRDLL.dll");
    strcpy_s(dll_full_path, g_config.inject_dll_path);

    LOG_F(INFO, "DLL Inject into process: %d\n", target_pid);
    LOG_F(INFO, "    DLL: %s\n", dll_full_path);

    // Opening the process with necessary privileges 
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, target_pid);
    if (hProcess == NULL) {
        LOG_F(ERROR, "Can't open handle, error: % lu\n", GetLastError());
        return FALSE;
    }
    //printf("\tOpen handle on PID: %d\n", target_pid);

    // Looking for the LoadLibraryA function in the kernel32.dll
    FARPROC loadLibAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
    if (loadLibAddress == NULL) {
        LOG_F(ERROR, "Could not find LoadLibraryA, error: %lu\n", GetLastError());
        return FALSE;
    }
    //printf("\tFound LoadLibraryA function\n");

    // Allocating some RWX memory
    LPVOID vae_buffer;
    vae_buffer = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (vae_buffer == NULL) {
        LOG_F(ERROR, "Can't allocate memory, error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }
    //printf("\tAllocated: %d bytes\n", MAX_PATH);

    // Writing the path of the DLL to inject x64\Debug\MyDumbEDRDLL
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, vae_buffer, dll_full_path, MAX_PATH, &bytesWritten)) {
        LOG_F(ERROR, "Can't write into memory, error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, vae_buffer, MESSAGE_SIZE, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    //printf("\tWrote %zu in %d process memory\n", bytesWritten, target_pid);

    // Creating a thread that will call LoadLibraryA and the path of the MyDUMBEDRDLL to load as argument
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibAddress, vae_buffer, 0, NULL);
    if (hThread == NULL) {
        LOG_F(ERROR, "Can't launch remote thread, error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, vae_buffer, MESSAGE_SIZE, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    LOG_F(INFO, "    Looks like successo\n");

    VirtualFreeEx(hProcess, vae_buffer, MESSAGE_SIZE, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}


BOOL piper() {
    LPCWSTR pipeName = L"\\\\.\\pipe\\dumbedr-injector";
    DWORD bytesRead = 0;

    // Creates a named pipe
    HANDLE hServerPipe = CreateNamedPipe(
        pipeName,                 // Pipe name to create
        PIPE_ACCESS_DUPLEX,       // Whether the pipe is supposed to receive or send data (can be both)
        PIPE_TYPE_MESSAGE,        // Pipe mode (whether or not the pipe is waiting for data)
        PIPE_UNLIMITED_INSTANCES, // Maximum number of instances from 1 to PIPE_UNLIMITED_INSTANCES
        MESSAGE_SIZE,             // Number of bytes for output buffer
        MESSAGE_SIZE,             // Number of bytes for input buffer
        0,                        // Pipe timeout 
        NULL                      // Security attributes (anonymous connection or may be needs credentials. )
    );

    while (TRUE) {

        // ConnectNamedPipe enables a named pipe server to start listening for incoming connections
        BOOL isPipeConnected = ConnectNamedPipe(
            hServerPipe, // Handle to the named pipe
            NULL         // Whether or not the pipe supports overlapped operations
        );

        wchar_t message[MESSAGE_SIZE] = { 0 };

        if (isPipeConnected) {

            // Read from the named pipe
            ReadFile(
                hServerPipe,  // Handle to the named pipe
                &message,     // Target buffer where to stock the output
                MESSAGE_SIZE, // Size of the buffer
                &bytesRead,   // Number of bytes read from ReadFile
                NULL          // Whether or not the pipe supports overlapped operations
            );

            // Casting the message into a DWORD
            DWORD target_pid = _wtoi(message);
            printf("~> Received process id %d\n", target_pid);

            remote_inject(target_pid);


            wchar_t response[MESSAGE_SIZE] = { 0 };
            swprintf_s(response, MESSAGE_SIZE, L"OK\0");
            DWORD pipeBytesWritten = 0;
            // Write to the named pipe
            WriteFile(
                hServerPipe,       // Handle to the named pipe
                response,          // Buffer to write from
                MESSAGE_SIZE,      // Size of the buffer 
                &pipeBytesWritten, // Numbers of bytes written
                NULL               // Whether or not the pipe supports overlapped operations
            );

            // Disconnect
            DisconnectNamedPipe(
                hServerPipe // Handle to the named pipe
            );

            printf("\n\n");
        }
    }
}

