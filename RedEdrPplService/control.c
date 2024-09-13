#include <stdio.h>
#include <Windows.h>

#include "emitter.h"
#include "control.h"
#include "../Shared/common.h"


HANDLE control_pipe = NULL;
HANDLE control_thread = NULL;

BOOL keep_running = TRUE;



DWORD start_child_process(wchar_t *childCMD2)
{
    DWORD retval = 0;
    WCHAR childCMD[MAX_BUF_SIZE] = L"C:\\RedEdr\\RedEdrPplRemover.exe";
    DWORD dataSize = MAX_BUF_SIZE;
    log_message(L"[PPL_RUNNER] start_child_process: Starting");

    // Get Command to run from registry
    //log_message(L"[PPL_RUNNER] start_child_process: Looking for command in RegKey: HKLM\\%s\n", CMD_REGKEY);
    //retval = RegGetValue(HKEY_LOCAL_MACHINE, CMD_REGKEY, NULL, RRF_RT_REG_SZ, NULL, &childCMD, &dataSize);
    //if (retval != ERROR_SUCCESS) {
    //    log_message(L"[PPL_RUNNER] start_child_process: RegGetValue Error: %d\n", retval);
    //    return retval;
    //}

    // Create Attribute List
    STARTUPINFOEXW StartupInfoEx = { 0 };
    SIZE_T AttributeListSize = 0;
    StartupInfoEx.StartupInfo.cb = sizeof(StartupInfoEx);
    InitializeProcThreadAttributeList(NULL, 1, 0, &AttributeListSize);
    if (AttributeListSize == 0) {
        retval = GetLastError();
        log_message(L"[PPL_RUNNER] start_child_process: InitializeProcThreadAttributeList1 Error: %d\n", retval);
        return retval;
    }
    StartupInfoEx.lpAttributeList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, AttributeListSize);
    if (InitializeProcThreadAttributeList(StartupInfoEx.lpAttributeList, 1, 0, &AttributeListSize) == FALSE) {
        retval = GetLastError();
        log_message(L"[PPL_RUNNER] start_child_process: InitializeProcThreadAttributeList2 Error: %d\n", retval);
        return retval;
    }

    // Set ProtectionLevel to be the same, i.e. PPL
    DWORD ProtectionLevel = PROTECTION_LEVEL_SAME;
    if (UpdateProcThreadAttribute(StartupInfoEx.lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
        &ProtectionLevel,
        sizeof(ProtectionLevel),
        NULL,
        NULL) == FALSE)
    {
        retval = GetLastError();
        log_message(L"[PPL_RUNNER] start_child_process: UpdateProcThreadAttribute Error: %d\n", retval);
        return retval;
    }

    // Start Process (hopefully)
    PROCESS_INFORMATION ProcessInformation = { 0 };
    log_message(L"[PPL_RUNNER] start_child_process: Creating Process3: '%s'\n", childCMD);
    if (CreateProcess(NULL,
        *childCMD,
        NULL,
        NULL,
        FALSE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_PROTECTED_PROCESS,
        NULL,
        NULL,
        (LPSTARTUPINFOW)&StartupInfoEx,
        &ProcessInformation) == FALSE)
    {
        retval = GetLastError();
        if (retval == ERROR_INVALID_IMAGE_HASH) {
            log_message(L"[PPL_RUNNER] start_child_process: CreateProcess Error: Invalid Certificate\n");
        }
        else {
            log_message(L"[PPL_RUNNER] start_child_process: CreateProcess Error: %d\n", retval);
        }
        return retval;
    }

    // Don't wait on process handle, we're setting our child free into the wild
    // This is to prevent any possible deadlocks

    log_message(L"[PPL_RUNNER] start_child_process finished");
    return retval;
}


void rededr_remove_service() {
    //wchar_t* cmd = L"C:\\RedEdr\\RedEdr.exe --pplstop";
    WCHAR childCMD[MAX_BUF_SIZE] = { 0 };
    //wcscpy_s(childCMD, MAX_BUF_SIZE, L"C:\\windows\\system32\\cmd.exe /c \"echo AAA > c:\\rededr\\aa\"");
    //wcscpy_s(childCMD, MAX_BUF_SIZE, L"C:\\RedEdr\\RedEdr.exe --pplstop");
    wcscpy_s(childCMD, MAX_BUF_SIZE, L"C:\\RedEdr\\RedEdrPplRemover.exe");
    start_child_process(childCMD);
}




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
                    rededr_remove_service();
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