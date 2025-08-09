
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


PipeServer::PipeServer(std::string pipe_name, wchar_t *pipePath) {
    hPipe = NULL;
    pipe_name = pipe_name;
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
        LOG_A(LOG_WARNING, "PipingSrv %s: Pipe already started", pipe_name.c_str());
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
            LOG_A(LOG_ERROR, "PipingSrv %s: Failed to create security descriptor. Error: %lu", 
                pipe_name.c_str(),
                GetLastError());
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
        LOG_A(LOG_ERROR, "PipingSrv %s: Error creating named pipe: %ld", 
            pipe_name.c_str(),
            GetLastError());
        hPipe = NULL;
        return FALSE;
    }

    return TRUE;
}


BOOL PipeServer::WaitForClient() {
    if (hPipe == NULL || hPipe == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "PipingSrv %s: Invalid pipe handle in WaitForClient",
            pipe_name.c_str());
        return FALSE;
    }

    // Wait for the client to connect
    if (! ConnectNamedPipe(hPipe, NULL)) {
		DWORD err = GetLastError();
        if (err != ERROR_PIPE_CONNECTED) {
            LOG_A(LOG_ERROR, "PipingSrv %s: Error handling client connection: %ld", 
                pipe_name.c_str(),
                err);
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
        LOG_A(LOG_ERROR, "PipingSrv %s: Attempt to send to closed pipe",
            pipe_name.c_str());
        return FALSE;
    }
    if (buffer == NULL) {
        LOG_A(LOG_ERROR, "PipingSrv %s: Null buffer provided",
            pipe_name.c_str());
        return FALSE;
    }
    
    size_t buffer_len = strlen(buffer);
    if (buffer_len == 0) {
        LOG_A(LOG_ERROR, "PipingSrv %s: Empty buffer provided",
            pipe_name.c_str());
        return FALSE;
    }
    
    // Check for potential overflow
    if (buffer_len >= PIPE_BUFFER_SIZE) {
        LOG_A(LOG_ERROR, "PipingSrv %s: Buffer too large for pipe",
            pipe_name.c_str());
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
        LOG_A(LOG_ERROR, "PipingSrv %s: Incomplete write to pipe",
            pipe_name.c_str());
        return FALSE;
    }
    
    return TRUE;
}


BOOL PipeServer::Receive(char* buffer, size_t buffer_len) {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (hPipe == NULL || hPipe == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "PipingSrv %s: Pipe is not connected", 
            pipe_name.c_str());
        return FALSE;
    }
    if (buffer == NULL || buffer_len == 0) {
        LOG_A(LOG_ERROR, "PipingSrv %s: Invalid buffer parameters",
            pipe_name.c_str());
        return FALSE;
    }
    
    // Ensure we don't exceed DWORD limits
    if (buffer_len > MAXDWORD) {
        LOG_A(LOG_ERROR, "PipingSrv %s: Buffer size too large",
            pipe_name.c_str());
        return FALSE;
    }
    
    DWORD readLen = static_cast<DWORD>(buffer_len - 1); // Reserve space for null terminator
    DWORD bytesRead = 0;
    
    if (!ReadFile(hPipe, buffer, readLen, &bytesRead, NULL)) {
        LOG_A(LOG_INFO, "PipingSrv %s: Error when reading from pipe: %lu", 
            pipe_name.c_str(),
            GetLastError());
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
        LOG_A(LOG_ERROR, "PipingSrv %s: Pipe not connected in ReceiveBatch", 
            pipe_name.c_str());
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
            LOG_A(LOG_INFO, "PipingSrv: %s: disconnected", 
                pipe_name.c_str());
        }
        else {
            LOG_A(LOG_ERROR, "PipingSrv: %s: Error reading from named pipe: %lu", 
                pipe_name.c_str(), 
                error);
        }
        // Close the pipe on any error to prevent further use
        CloseHandle(hPipe);
        hPipe = NULL;
    }

    return strings;
}


void PipeServer::Shutdown() {
    std::lock_guard<std::mutex> lock(pipe_mutex);

    LOG_A(LOG_INFO, "PipingSrv %s: Shutdown",
        pipe_name.c_str());
    
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

PipeClient::PipeClient(std::string pipeName) {
    hPipe = NULL;
    pipe_name = pipeName;
}

PipeClient::~PipeClient() {
    Disconnect();
}


BOOL PipeClient::Connect(const wchar_t *pipe_path) {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (pipe_path == NULL) {
        LOG_A(LOG_ERROR, "PipingCli %s: Null pipe path provided",
            pipe_name.c_str());
        return FALSE;
    }
    
    // Close existing connection if any
    if (hPipe != NULL && hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
    }
    
    hPipe = CreateFileW(pipe_path, GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_INFO, "PipingCli %s: Could not open pipe. Error: %lu", 
            pipe_name.c_str(),
            GetLastError());
        hPipe = NULL;
        return FALSE;
    }
    return TRUE;
}


void PipeClient::Disconnect() {
    LOG_A(LOG_INFO, "PipingCli %s: Disconnect",
        pipe_name.c_str());
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (hPipe != NULL && hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
    }
    hPipe = NULL;
}


BOOL PipeClient::Send(char* buffer) {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (hPipe == NULL || hPipe == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "PipingCli %s: Pipe closed",
            pipe_name.c_str());
        return FALSE;
    }
    if (buffer == NULL) {
        LOG_A(LOG_ERROR, "PipingCli %s: Null buffer provided",
            pipe_name.c_str());
        return FALSE;
    }
    
    size_t buffer_len = strlen(buffer);
    if (buffer_len == 0) {
        LOG_A(LOG_ERROR, "PipingCli %s: Empty buffer provided",
            pipe_name.c_str());
        return FALSE;
    }
    
    // Check for potential overflow
    if (buffer_len >= PIPE_BUFFER_SIZE) {
        LOG_A(LOG_ERROR, "PipingCli %s: Buffer too large for pipe",
            pipe_name.c_str());
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
        LOG_A(LOG_ERROR, "PipingCli %s: Incomplete write to pipe",
            pipe_name.c_str());
        return FALSE;
    }
    
    return TRUE;
}


BOOL PipeClient::Receive(char* buffer, size_t buffer_len) {
    std::lock_guard<std::mutex> lock(pipe_mutex);
    
    if (hPipe == NULL || hPipe == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "PipingCli %s: Pipe is not connected",
            pipe_name.c_str());
        return FALSE;
    }
    if (buffer == NULL || buffer_len == 0) {
        LOG_A(LOG_ERROR, "PipingCli %s: Invalid buffer parameters",
            pipe_name.c_str());
        return FALSE;
    }
    
    // Ensure we don't exceed DWORD limits
    if (buffer_len > MAXDWORD) {
        LOG_A(LOG_ERROR, "PipingCli %s: Buffer size too large",
            pipe_name.c_str());
        return FALSE;
    }
    
    DWORD readLen = static_cast<DWORD>(buffer_len - 1); // Reserve space for null terminator
    DWORD bytesRead = 0;
    
    if (!ReadFile(hPipe, buffer, readLen, &bytesRead, NULL)) {
        LOG_A(LOG_INFO, "PipingCli %s: Error reading from pipe: %lu", 
            pipe_name.c_str(),
            GetLastError());
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
