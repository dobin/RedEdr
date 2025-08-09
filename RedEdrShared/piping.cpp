
#include <Windows.h>
#include <sddl.h>
#include <iostream>
#include <vector>
#include <string>

#include "piping.h"
#include "../Shared/common.h"


// The implementation is in each solution
void LOG_W(int verbosity, const wchar_t* format, ...);
void LOG_A(int verbosity, const char* format, ...);


/* Piping.ch: Provide pipes for communication with components
 *   server and client
 *   send, receive, receive-batch
 */


PipeServer::PipeServer(std::string pipeName, wchar_t *pipePath) {
    hPipe = NULL;
    pipe_name = pipeName;
    pipe_path = pipePath;
}

PipeServer::~PipeServer() {
    Shutdown();
}


BOOL PipeServer::StartAndWaitForClient(BOOL allow_all) {
    if (!Start(allow_all)) {
        return FALSE;
    }
    return WaitForClient();
}


BOOL PipeServer::Start(BOOL allow_all) {
    if (hPipe != NULL) {
        LOG_A(LOG_WARNING, "Piping Server: Pipe already started");
        return FALSE;
    }

    // Permissions
    // Allow processes of all privilege levels to access this pipe
    SECURITY_ATTRIBUTES* sa_ptr = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    
    if (allow_all) {
        // "D:(A;OICI;GA;;;WD)" translates to: Allow (A) All Users (WD) Generic Access (GA)
        LPCWSTR securityDescriptorString = L"D:(A;OICI;GA;;;WD)";
        SECURITY_ATTRIBUTES sa;
        
        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            securityDescriptorString,
            SDDL_REVISION_1,
            &pSD,
            NULL))
        {
            LOG_A(LOG_ERROR, "Piping Server: Failed to create security descriptor. Error: %lu", GetLastError());
            return FALSE;
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
    
    // Free the security descriptor if it was allocated
    if (pSD != NULL) {
        LocalFree(pSD);
    }
    
    if (hPipe == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "Piping Server: Error creating named pipe: %ld", GetLastError());
        hPipe = NULL;
        return FALSE;
    }

    return TRUE;
}


BOOL PipeServer::WaitForClient() {
    if (hPipe == NULL || hPipe == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "Piping Server: Invalid pipe handle in WaitForClient");
        return FALSE;
    }

    // Wait for the client to connect
    if (! ConnectNamedPipe(hPipe, NULL)) {
		DWORD err = GetLastError();
        if (err != ERROR_PIPE_CONNECTED) {
            LOG_A(LOG_ERROR, "Piping Server: Error handling client connection: %ld", err);
            CloseHandle(hPipe);
            hPipe = NULL;
            return FALSE;
        }
    }

    return TRUE;
}


BOOL PipeServer::Send(char* buffer) {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (hPipe == NULL || hPipe == INVALID_HANDLE_VALUE) {
        LOG_W(LOG_ERROR, L"Piping Server: Attempt to send to closed pipe");
        return FALSE;
    }
    if (buffer == NULL) {
        LOG_W(LOG_ERROR, L"Piping Server: Null buffer provided");
        return FALSE;
    }
    
    size_t buffer_len = strlen(buffer);
    if (buffer_len == 0) {
        LOG_W(LOG_ERROR, L"Piping Server: Empty buffer provided");
        return FALSE;
    }
    
    // Check for potential overflow
    if (buffer_len >= PIPE_BUFFER_SIZE) {
        LOG_W(LOG_ERROR, L"Piping Server: Buffer too large for pipe");
        return FALSE;
    }
    
    DWORD len = static_cast<DWORD>(buffer_len) + 1; // include null terminator
    DWORD bytesWritten = 0;
    
    if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
        // Let caller handle it
        return FALSE;
    }
    
    // Verify all bytes were written
    if (bytesWritten != len) {
        LOG_W(LOG_ERROR, L"Piping Server: Incomplete write to pipe");
        return FALSE;
    }
    
    return TRUE;
}


BOOL PipeServer::Receive(char* buffer, size_t buffer_len) {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (hPipe == NULL || hPipe == INVALID_HANDLE_VALUE) {
        LOG_W(LOG_ERROR, L"Piping Server: Pipe is not connected");
        return FALSE;
    }
    if (buffer == NULL || buffer_len == 0) {
        LOG_W(LOG_ERROR, L"Piping Server: Invalid buffer parameters");
        return FALSE;
    }
    
    // Ensure we don't exceed DWORD limits
    if (buffer_len > MAXDWORD) {
        LOG_W(LOG_ERROR, L"Piping Server: Buffer size too large");
        return FALSE;
    }
    
    DWORD readLen = static_cast<DWORD>(buffer_len - 1); // Reserve space for null terminator
    DWORD bytesRead = 0;
    
    if (!ReadFile(hPipe, buffer, readLen, &bytesRead, NULL)) {
        LOG_W(LOG_INFO, L"Piping Server: Error when reading from pipe: %lu", GetLastError());
        return FALSE;
    }
    
    // Ensure null termination
    if (bytesRead < buffer_len) {
        buffer[bytesRead] = '\0';
    } else {
        buffer[buffer_len - 1] = '\0';
    }
    
    return TRUE;
}


// Empty result = error / finished
// Currently no batching
std::vector<std::string> PipeServer::ReceiveBatch() {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    DWORD bytesRead;
    std::vector<std::string> strings;

    if (hPipe == NULL || hPipe == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "Piping: %s: Pipe not connected in ReceiveBatch", pipe_name.c_str());
        return strings;
    }

    if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL)) {
        // Ensure null termination
        buffer[bytesRead] = '\0';
        
        // Validate that we have valid data
        if (bytesRead > 0) {
            strings.push_back(std::string(buffer));
        }
    }
    else {
        DWORD error = GetLastError();
        if (error == ERROR_BROKEN_PIPE) {
            LOG_A(LOG_INFO, "Piping: %s: disconnected", pipe_name.c_str());
        }
        else {
            LOG_A(LOG_ERROR, "Piping: %s: Error reading from named pipe: %lu", pipe_name.c_str(), error);
        }
        // Close the pipe on any error to prevent further use
        CloseHandle(hPipe);
        hPipe = NULL;
    }

    return strings;
}


void PipeServer::Shutdown() {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (hPipe != NULL && hPipe != INVALID_HANDLE_VALUE) {
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }
    hPipe = NULL;
}


BOOL PipeServer::IsConnected() {
    return (hPipe != NULL && hPipe != INVALID_HANDLE_VALUE);
}


/* Client */

PipeClient::PipeClient() {
    hPipe = NULL;
}

PipeClient::~PipeClient() {
    Disconnect();
}


BOOL PipeClient::Connect(const wchar_t *pipe_path) {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (pipe_path == NULL) {
        LOG_W(LOG_ERROR, L"Piping Client: Null pipe path provided");
        return FALSE;
    }
    
    // Close existing connection if any
    if (hPipe != NULL && hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
    }
    
    hPipe = CreateFileW(pipe_path, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        LOG_W(LOG_INFO, L"Piping Client: Could not open pipe. Error: %lu", GetLastError());
        hPipe = NULL;
        return FALSE;
    }
    return TRUE;
}


void PipeClient::Disconnect() {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (hPipe != NULL && hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
    }
    hPipe = NULL;
}


BOOL PipeClient::Send(char* buffer) {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (hPipe == NULL || hPipe == INVALID_HANDLE_VALUE) {
        LOG_W(LOG_ERROR, L"Piping Client: Pipe closed");
        return FALSE;
    }
    if (buffer == NULL) {
        LOG_W(LOG_ERROR, L"Piping Client: Null buffer provided");
        return FALSE;
    }
    
    size_t buffer_len = strlen(buffer);
    if (buffer_len == 0) {
        LOG_W(LOG_ERROR, L"Piping Client: Empty buffer provided");
        return FALSE;
    }
    
    // Check for potential overflow
    if (buffer_len >= PIPE_BUFFER_SIZE) {
        LOG_W(LOG_ERROR, L"Piping Client: Buffer too large for pipe");
        return FALSE;
    }
    
    DWORD len = static_cast<DWORD>(buffer_len) + 1; // include null terminator
    DWORD bytesWritten = 0;
    
    BOOL res = WriteFile(hPipe, buffer, len, &bytesWritten, NULL);
    if (res == FALSE) {
        return FALSE;
    }
    
    // Verify all bytes were written
    if (bytesWritten != len) {
        LOG_W(LOG_ERROR, L"Piping Client: Incomplete write to pipe");
        return FALSE;
    }
    
    return TRUE;
}


BOOL PipeClient::Receive(char* buffer, size_t buffer_len) {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (hPipe == NULL || hPipe == INVALID_HANDLE_VALUE) {
        LOG_W(LOG_ERROR, L"Piping Client: Pipe is not connected");
        return FALSE;
    }
    if (buffer == NULL || buffer_len == 0) {
        LOG_W(LOG_ERROR, L"Piping Client: Invalid buffer parameters");
        return FALSE;
    }
    
    // Ensure we don't exceed DWORD limits
    if (buffer_len > MAXDWORD) {
        LOG_W(LOG_ERROR, L"Piping Client: Buffer size too large");
        return FALSE;
    }
    
    DWORD readLen = static_cast<DWORD>(buffer_len - 1); // Reserve space for null terminator
    DWORD bytesRead = 0;
    
    if (!ReadFile(hPipe, buffer, readLen, &bytesRead, NULL)) {
        LOG_W(LOG_INFO, L"Piping Client: Error reading from pipe: %lu", GetLastError());
        return FALSE;
    }
    
    // Ensure null termination
    if (bytesRead < buffer_len) {
        buffer[bytesRead] = '\0';
    } else {
        buffer[buffer_len - 1] = '\0';
    }
    
    return TRUE;
}
