
#include <Windows.h>
#include <sddl.h>
#include <iostream>
#include <vector>
#include <string>

#include "piping.h"
#include "logging.h"
#include "../Shared/common.h"


/* Piping.ch: Provide pipes for communication with components
 *   server and client
 *   send, receive, receive-batch
 */


PipeServer::PipeServer(std::string pipeName, wchar_t *pipePath) {
    hPipe = NULL;
    pipe_name = pipeName;
    pipe_path = pipePath;
}


BOOL PipeServer::StartAndWaitForClient(BOOL allow_all) {
    if (!Start(allow_all)) {
        return FALSE;
    }
    return WaitForClient();
}


BOOL PipeServer::Start(BOOL allow_all) {
    // Permissions
    // Allow processes of all privilege levels to access this pipe
    SECURITY_ATTRIBUTES* sa_ptr = NULL;
    if (allow_all) {
        // "D:(A;OICI;GA;;;WD)" translates to: Allow (A) All Users (WD) Generic Access (GA)
        LPCWSTR securityDescriptorString = L"D:(A;OICI;GA;;;WD)";
        SECURITY_ATTRIBUTES sa;
        PSECURITY_DESCRIPTOR pSD = NULL;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            securityDescriptorString,
            SDDL_REVISION_1,
            &pSD,
            NULL))
        {
            LOG_A(LOG_ERROR, "Piping Server: Failed to create security descriptor. Error: %lu", GetLastError());
            return NULL;
        }
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.lpSecurityDescriptor = pSD;
        sa.bInheritHandle = FALSE;
        sa_ptr = &sa;
    }

    hPipe = CreateNamedPipe(
        pipe_path,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE| PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        0,
        sa_ptr
    );
    if (hPipe == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "Piping Server: Error creating named pipe: %ld", GetLastError());
        hPipe = NULL;
        return FALSE;
    }

    return TRUE;
}


BOOL PipeServer::WaitForClient() {
    // Wait for the client to connect
    if (! ConnectNamedPipe(hPipe, NULL)) {
		DWORD err = GetLastError();
        if (err != ERROR_PIPE_CONNECTED) { // wtf is this
            LOG_A(LOG_ERROR, "Piping Server: Error handling client connection: %ld", err);
            CloseHandle(hPipe);
            hPipe = NULL;
            return FALSE;
        }
    }

    return TRUE;
}


BOOL PipeServer::Send(char* buffer) {
    if (hPipe == NULL) {
        LOG_W(LOG_ERROR, L"Piping Server: Attempt to send to closed pipe");
        return FALSE;
    }
    DWORD len = strlen(buffer) + 1; // -> include two trailing 0 bytes
    if (! WriteFile(hPipe, buffer, len, NULL, NULL)) {
        // Let caller handle it
        //LOG_W(LOG_ERROR, L"Piping Server: Error when sending to pipe: %d", GetLastError());
        return FALSE;
    }
    return TRUE;
}


BOOL PipeServer::Receive(char* buffer, size_t buffer_len) {
    DWORD readLen = static_cast<DWORD>(buffer_len);
    if (!ReadFile(hPipe, buffer, readLen, NULL, NULL)) {
        //LOG_W(LOG_INFO, L"Piping Server: Error when reading from pipe: %d", GetLastError());
        return FALSE;
    }
    return TRUE;
}


// Empty result = error / finished
// Currently no batching
std::vector<std::string> PipeServer::ReceiveBatch() {
    DWORD bytesRead;
    std::vector<std::string> strings;

    if (ReadFile(hPipe, buffer, sizeof(buffer), &bytesRead, NULL)) {
        strings.push_back(std::string(buffer));
    }
    else {
        if (GetLastError() == ERROR_BROKEN_PIPE) {
            LOG_A(LOG_INFO, "Piping: %s: disconnected",
                pipe_name.c_str());
            hPipe = NULL;
        }
        else {
            LOG_A(LOG_ERROR, "Piping: %s: Error reading from named pipe: %s",
                pipe_name.c_str());
            hPipe = NULL;
        }
    }

    return strings;
}


void PipeServer::Shutdown() {
    if (hPipe == NULL) {
        return;
    }
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
    hPipe = NULL;
}


BOOL PipeServer::IsConnected() {
    if (hPipe == NULL) {
        return FALSE;
    }
    else {
        return TRUE;
    }
}


/* Client */

PipeClient::PipeClient() {
    hPipe = NULL;
}


BOOL PipeClient::Connect(const wchar_t *pipe_path) {
    hPipe = CreateFileW(pipe_path, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        LOG_W(LOG_INFO, L"Piping Client: Could not open pipe");
        hPipe = NULL;
        return FALSE;
    }
    return TRUE;
}


void PipeClient::Disconnect() {
    CloseHandle(hPipe);
    hPipe = NULL;
}


BOOL PipeClient::Send(char* buffer) {
    BOOL res = 0;
    if (hPipe == NULL) {
        LOG_W(LOG_ERROR, L"Piping Client: Pipe closed");
        return FALSE;
    }
    DWORD len = (DWORD)strlen(buffer) + 1; // -> include trailing 0 bytes
    res = WriteFile(hPipe, buffer, len, NULL, NULL);
    if (res == FALSE) {
        //LOG_W(LOG_ERROR, L"Piping Client: Error when sending to pipe: %d", GetLastError());
        return FALSE;
    }
    return TRUE;
}


BOOL PipeClient::Receive(char* buffer, size_t buffer_len) {
    DWORD readLen = static_cast<DWORD>(buffer_len);
    if (!ReadFile(hPipe, buffer, readLen, NULL, NULL)) {
        LOG_W(LOG_INFO, L"Piping Client: Error reading from pipe: %lu", GetLastError());
        return FALSE;
    }
    return TRUE;
}
