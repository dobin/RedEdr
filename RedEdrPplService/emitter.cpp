#include <stdio.h>
#include <Windows.h>

#include "../Shared/common.h"
#include "logging.h"

HANDLE hPipe = NULL;


BOOL ConnectEmitterPipe() {
    LOG_W(LOG_INFO, L"Emitter: Connect pipe %s to RedEdr", DLL_PIPE_NAME);
    hPipe = CreateFile(DLL_PIPE_NAME, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        LOG_W(LOG_INFO, L"Emitter: Error connecting to pipe %s error %ld", 
            DLL_PIPE_NAME, GetLastError());
        return FALSE;
    }

    // Retrieve config (first packet)
    // this is the only read for this pipe
    char buffer[256];
    DWORD bytesRead;
    if (!ReadFile(hPipe, &buffer, 256, &bytesRead, NULL)) {
        LOG_W(LOG_INFO, L"Emitter: Could not read first message from pipe from RedEdr.exe: %lu. Abort.",
            GetLastError());
        return FALSE;
    }
    else {
        LOG_W(LOG_INFO, L"Emitter: Successfully read config");
    }

    // Ignore config atm
    /*if (strstr(buffer, "")) {
    }
    else {
    }
    */

    return TRUE;
}


void SendEmitterPipe(wchar_t* buffer) {
    DWORD pipeBytesWritten = 0;
    DWORD res = 0;
    if (hPipe == NULL) {
        LOG_W(LOG_INFO, L"Emitter: Error when sending as pipe is closed");
        return;
    }
    DWORD len = (DWORD)(wcslen(buffer) * 2) + 2; // +2 -> include two trailing 0 bytes
    res = WriteFile(hPipe, buffer, len, &pipeBytesWritten, NULL);
    if (res == FALSE) {
        LOG_W(LOG_INFO, L"Emitter: Error when sending to pipe");
    }
}


void DisconnectEmitterPipe() {
    LOG_W(LOG_INFO, L"Emitter: Disconnect pipe %s to RedEdr", DLL_PIPE_NAME);
    CloseHandle(hPipe);
    hPipe = NULL;
}
