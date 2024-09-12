#include <stdio.h>
#include <Windows.h>

#include "../Shared/common.h"

HANDLE hPipe = NULL;


BOOL ConnectEmitterPipe() {
    hPipe = CreateFile(DLL_PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        log_message(L"Error connecting to named pipe: %ld", GetLastError());
        return FALSE;
    }
    return TRUE;
}


void SendEmitterPipe(wchar_t* buffer) {
    DWORD pipeBytesWritten = 0;
    DWORD res = 0;
    if (hPipe == NULL) {
        log_message(L"SendDllPipe: Error when sending as pipe is closed");
        log_message(L"           : %s", buffer);
        return;
    }
    DWORD len = (DWORD)(wcslen(buffer) * 2) + 2; // +2 -> include two trailing 0 bytes
    res = WriteFile(hPipe, buffer, len, &pipeBytesWritten, NULL);
    if (res == FALSE) {
        log_message(L"SendDllPipe: Error when sending to pipe");
    }
}


void DisconnectEmitterPipe() {
    CloseHandle(hPipe);
    hPipe = NULL;
}
