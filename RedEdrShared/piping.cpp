
#include <Windows.h>
#include <sddl.h>
#include <iostream>
#include <vector>
#include <string>

#include "piping.h"
#include "logging.h"
#include "../Shared/common.h"


/* Server */

PipeServer::PipeServer(const wchar_t *pipe_name) {
    hPipe = NULL;
    name = pipe_name;
}


BOOL PipeServer::StartAndWaitForClient(const wchar_t *pipeName, BOOL allow_all) {
    // Permissions
    // Allow processes of all privilege levels to access this pipe
    SECURITY_ATTRIBUTES *sa_ptr = NULL;
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
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, //PIPE_TYPE_MESSAGE | PIPE_WAIT,
        PIPE_UNLIMITED_INSTANCES,
        PIPE_BUFFER_SIZE,
        PIPE_BUFFER_SIZE,
        0,
        sa_ptr
    );
    if (hPipe == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "Piping Server: Error creating named pipe: %ld", GetLastError());
        return FALSE;
    }

    //LOG_A(LOG_INFO, "DllReader: Waiting for client to connect...");
    // Wait for the client to connect
    if (! ConnectNamedPipe(hPipe, NULL)) {
        LOG_A(LOG_ERROR, "Piping Server: Error handling client connection: %ld", GetLastError());
        CloseHandle(hPipe);
        return FALSE;
    }

    return TRUE;
}


BOOL PipeServer::Send(wchar_t* buffer) {
    if (hPipe == NULL) {
        LOG_W(LOG_ERROR, L"Piping Server: Attempt to send to closed pipe");
        return FALSE;
    }
    DWORD len = (DWORD)(wcslen(buffer) + 1) * 2; // -> include two trailing 0 bytes
    if (! WriteFile(hPipe, buffer, len, NULL, NULL)) {
        // Let caller handle it
        //LOG_W(LOG_ERROR, L"Piping Server: Error when sending to pipe: %d", GetLastError());
        return FALSE;
    }
    return TRUE;
}


BOOL PipeServer::Receive(wchar_t* buffer, size_t buffer_len) {
    buffer_len *= 2; // Convert to bytes
    if (!ReadFile(hPipe, buffer, buffer_len, NULL, NULL)) {
        //LOG_W(LOG_INFO, L"Piping Server: Error when reading from pipe: %d", GetLastError());
        return FALSE;
    }
    return TRUE;
}


// Empty result = error / finished
std::vector<std::wstring> PipeServer::ReceiveBatch() {
    DWORD bytesRead, bytesWritten;
    std::vector<std::wstring> wstrings;

    if (ReadFile(hPipe, buf_ptr, sizeof(buffer) - rest_len, &bytesRead, NULL)) {
        //if (pipeServer->Receive(buf_ptr, sizeof(buffer) - rest_len))
        int full_len = rest_len + bytesRead; // full len including the previous shit, if any
        wchar_t* p = (wchar_t*)buffer; // pointer to the string we will print. points to buffer
        // which always contains the beginning of a string
        int last_potential_str_start = 0;
        for (int i = 0; i < full_len; i += 2) { // 2-byte increments because wide string
            if (buffer[i] == 0 && buffer[i + 1] == 0) { // check manually for \x00\x00
                //wprintf(L"DLL: %s\n", p); // found \x00\x00, print the previous string
                //do_output(std::wstring(p));
                wstrings.push_back(std::wstring(p));
                i += 2; // skip \x00\x00
                last_potential_str_start = i; // remember the last zero byte we found
                p = (wchar_t*)&buffer[i]; // init p with (potential) next string
            }
        }
        if (last_potential_str_start == 0) {
            LOG_A(LOG_ERROR, "DllReader: No 0x00 0x00 byte found, errornous input?");
        }

        if (last_potential_str_start != full_len) {
            // we didnt print until end of the buffer. so there's something left
            rest_len = full_len - last_potential_str_start; // how much is left
            memcpy(&buffer[0], &buffer[last_potential_str_start], rest_len); // copy that to the beginning of the buffer
            buf_ptr = &buffer[rest_len]; // point read buffer to after our rest
        }
        else {
            // printf till the end of the read data. 
            // always reset
            buf_ptr = &buffer[0];
            rest_len = 0;
        }
    }
    else {
        if (GetLastError() == ERROR_BROKEN_PIPE) {
            LOG_A(LOG_INFO, "DllReader: Injected DLL disconnected");
        }
        else {
            LOG_A(LOG_ERROR, "DllReader: Error reading from named pipe: %ld", GetLastError());
        }
    }

    return wstrings;
}


void PipeServer::Shutdown() {
    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}



/* Client */

PipeClient::PipeClient() {
    hPipe = NULL;
}


BOOL PipeClient::Connect(const wchar_t *pipeName) {
    hPipe = CreateFileW(pipeName, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
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


BOOL PipeClient::Send(wchar_t* buffer) {
    BOOL res = 0;
    if (hPipe == NULL) {
        LOG_W(LOG_ERROR, L"Piping Client: Pipe closed");
        return FALSE;
    }
    DWORD len = (DWORD)(wcslen(buffer) + 1) * 2; // -> include two trailing 0 bytes
    res = WriteFile(hPipe, buffer, len, NULL, NULL);
    if (res == FALSE) {
        LOG_W(LOG_ERROR, L"Piping Client: Error when sending to pipe: %d", GetLastError());
        return FALSE;
    }
    return TRUE;
}


BOOL PipeClient::Receive(wchar_t* buffer, size_t buffer_len) {
    buffer_len *= 2; // Convert to bytes
    if (!ReadFile(hPipe, buffer, buffer_len, NULL, NULL)) {
        LOG_W(LOG_INFO, L"Piping Client: Error reading from pipe: %lu", GetLastError());
        return FALSE;
    }
    return TRUE;
}
