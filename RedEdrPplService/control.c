#include <stdio.h>
#include <Windows.h>

#include "emitter.h"
#include "control.h"
#include "../Shared/common.h"


HANDLE control_pipe = NULL;
HANDLE control_thread = NULL;

BOOL keep_running = TRUE;


DWORD WINAPI ServiceControlPipeThread(LPVOID param) {
    wchar_t buffer[SMALL_PIPE];
    int rest_len = 0;
    DWORD bytesRead;
    memset(buffer, 0, sizeof(buffer));

    while (keep_running) {
        control_pipe = CreateNamedPipeW(PPL_SERVICE_PIPE_NAME, PIPE_ACCESS_INBOUND, PIPE_TYPE_MESSAGE,
            PIPE_UNLIMITED_INSTANCES, SMALL_PIPE, SMALL_PIPE, 0, NULL);
        if (control_pipe == INVALID_HANDLE_VALUE) {
            log_message(L"PplService: Error creating named pipe: %ld", GetLastError());
            return 1;
        }

        log_message(L"PplService: Waiting for client (Kernel Driver) to connect...");

        // Wait for the client to connect
        BOOL result = ConnectNamedPipe(control_pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!result) {
            log_message(L"PplService: Error connecting to named pipe: %ld", GetLastError());
            CloseHandle(control_pipe);
            return 1;
        }

        log_message(L"PplService: connected");

        while (keep_running) {
            // Read data from the pipe
            if (!ReadFile(control_pipe, buffer, SMALL_PIPE, &bytesRead, NULL)) {
                if (GetLastError() == ERROR_BROKEN_PIPE) {

                    log_message(L"PplService: Disconnected: %ld", GetLastError());
                    break;
                }
                else {
                    log_message(L"PplService: Error reading from named pipe: %ld", GetLastError());
                    break;
                }
            }
            else {
                buffer[bytesRead] = L"\0";
                if (wcscmp(buffer, L"start") == 0) {
                    log_message(L"-> start");
                    ConnectEmitterPipe(); // Connect to the RedEdr pipe
                    enable_consumer(TRUE);
                }
                else if (wcscmp(buffer, L"stop") == 0) {
                    log_message(L"-> stop");
                    enable_consumer(FALSE);
                    DisconnectEmitterPipe(); // Disconnect the RedEdr pipe
                }
                else if (wcscmp(buffer, L"shutdown") == 0) {
                    log_message(L"-> shutdown");
                    stop_control(); // stop this thread
                    shutdown_etwti_reader(); // also makes main return
                    break;
                }
                else {
                    log_message(L"READ DATA: %s", buffer);
                    SendEmitterPipe(buffer);
                }
            }
        }

        // Close the pipe
        if (control_pipe != NULL) {
            CloseHandle(control_pipe);
            control_pipe = NULL;
        }
    }
    log_message(L"PplService: Quit");
    return 0;
}


void start_control() {
    log_message(L"> start control");
    control_thread = CreateThread(NULL, 0, ServiceControlPipeThread, NULL, 0, NULL);
    if (control_thread == NULL) {
        log_message(L"Failed to create thread");
    }
}


void stop_control() {
    log_message(L"> stop control");
    keep_running = FALSE;

    // Send some stuff so the ReadFile() in the reader thread returns
    DWORD dwWritten;
    BOOL success = WriteFile(control_pipe, "", 0, &dwWritten, NULL);

    //CloseHandle(control_pipe);
    //control_pipe = NULL;
}