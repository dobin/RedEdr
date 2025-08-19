#include <stdio.h>
#include <Windows.h>

#include "control.h"
#include "emitter.h"
#include "../Shared/common.h"
#include "logging.h"
#include "objcache.h"
#include "etwtireader.h"
#include "piping.h"
#include "utils.h"
#include "json.hpp"

DWORD start_child_process(wchar_t* childCMD);


HANDLE control_thread = NULL;
volatile BOOL keep_running = TRUE; // Made volatile for thread safety

PipeServer pipeServer = PipeServer("RedEdrPPL Server", (wchar_t*)PPL_SERVICE_PIPE_NAME);


DWORD WINAPI ServiceControlPipeThread(LPVOID param) {
    char buffer[PPL_CONFIG_LEN];

    while (keep_running) {
        LOG_W(LOG_INFO, L"Control: Waiting for client (RedEdr.exe) to connect...");
        if (!pipeServer.StartAndWaitForClient(false)) {
            LOG_A(LOG_ERROR, "Error waiting for RedEdr.exe");
            continue;
        }
        LOG_A(LOG_INFO, "Control: Client connected");
        LOG_A(LOG_INFO, "Control: Connect us back to RedEdr");
        if (!ConnectEmitterPipe()) { // Connect to the RedEdr pipe
            LOG_A(LOG_ERROR, "Control: Failed to connect to RedEdr pipe");
            //break; // Exit the loop if connection fails
        }

        while (keep_running) {
            LOG_A(LOG_INFO, "Control: Wait for command");
            memset(buffer, 0, sizeof(buffer));
            if (!pipeServer.Receive(buffer, PPL_CONFIG_LEN)) {
                LOG_A(LOG_ERROR, "Error waiting for RedEdr.exe command");
                break;
            }

            LOG_A(LOG_INFO, "Control: Received command: %s", buffer);
            
            try {
                // Try to parse as JSON first
                nlohmann::json j = nlohmann::json::parse(buffer);
                
                if (j.contains("command")) {
                    std::string command = j["command"];
                    
                    if (command == "start") {
                        if (j.contains("targets") && j["targets"].is_array()) {
                            LOG_A(LOG_INFO, "Control: Processing start command with %zu targets", j["targets"].size());
                            std::vector<std::string> targets = j["targets"];
                            set_target_names(targets);
                        } else {
                            LOG_A(LOG_ERROR, "Control: Start command missing 'targets' array");
                        }
                    }
                    else if (command == "shutdown") {
                        LOG_A(LOG_INFO, "Control: Received JSON command: shutdown");
                        keep_running = FALSE; // Signal thread to stop
                        g_ServiceStopping = TRUE; // Signal main service loop to stop
                        ShutdownEtwtiReader(); // also makes main return
                        break;
                    }
                    else {
                        LOG_A(LOG_INFO, "Control: Unknown JSON command: %s", command.c_str());
                    }
                } else {
                    LOG_A(LOG_ERROR, "Control: JSON missing 'command' field");
                }
            }
            catch (const nlohmann::json::parse_error& e) {
                // Fallback to legacy string-based parsing for backward compatibility
                LOG_A(LOG_WARNING, "Control: JSON parse failed %s", e.what());
            }
        }

		LOG_A(LOG_INFO, "Control: Client disconnected, shutting down pipe");
        pipeServer.Shutdown();
    }
    LOG_A(LOG_INFO, "Control: Finished");
    return 0;
}


void StartControl() {
    LOG_W(LOG_INFO, L"Control: Start Thread");
    
    // Reset the running flag
    keep_running = TRUE;
    
    control_thread = CreateThread(NULL, 0, ServiceControlPipeThread, NULL, 0, NULL);
    if (control_thread == NULL) {
        DWORD error = GetLastError();
        LOG_W(LOG_ERROR, L"Control: Failed to create thread, error: %d", error);
    } else {
        LOG_W(LOG_INFO, L"Control: Thread created successfully");
    }
}


void StopControl() {
    LOG_W(LOG_INFO, L"Control: Stop Thread");

    // Signal the thread to stop
    keep_running = FALSE;

    // Send empty data to unblock any pending pipe operations
    pipeServer.Send((char*)"");

    // Wait for the thread to finish (with timeout)
    if (control_thread != NULL) {
        DWORD waitResult = WaitForSingleObject(control_thread, 5000); // 5 second timeout
        if (waitResult == WAIT_TIMEOUT) {
            LOG_W(LOG_ERROR, L"Control: Thread did not stop gracefully, terminating");
            TerminateThread(control_thread, 1);
        }
        CloseHandle(control_thread);
        control_thread = NULL;
    }
}


//////


// broken atm
void rededr_remove_service() {
    //wchar_t* cmd = L"C:\\RedEdr\\RedEdr.exe --pplstop";
    WCHAR childCMD[PATH_LEN] = { 0 };
    //wcscpy_s(childCMD, PATH_LEN, L"C:\\windows\\system32\\cmd.exe /c \"echo AAA > c:\\rededr\\aa\"");
    //wcscpy_s(childCMD, PATH_LEN, L"C:\\RedEdr\\RedEdrPplRemover.exe");
    wcscpy_s(childCMD, PATH_LEN, L"C:\\RedEdr\\RedEdr.exe --pplstop");
    start_child_process(childCMD);
}


DWORD start_child_process(wchar_t* childCMD)
{
    DWORD retval = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList = NULL;
    PROCESS_INFORMATION ProcessInformation = { 0 };
    DWORD ProtectionLevel = PROTECTION_LEVEL_SAME;


    if (childCMD == NULL) {
        LOG_W(LOG_ERROR, L"start_child_process: Invalid command parameter");
        return ERROR_INVALID_PARAMETER;
    }
    
    LOG_W(LOG_INFO, L"start_child_process: Starting");

    // Create Attribute List
    STARTUPINFOEXW StartupInfoEx = { 0 };
    SIZE_T AttributeListSize = 0;
    StartupInfoEx.StartupInfo.cb = sizeof(StartupInfoEx);
    
    InitializeProcThreadAttributeList(NULL, 1, 0, &AttributeListSize);
    if (AttributeListSize == 0) {
        retval = GetLastError();
        LOG_W(LOG_ERROR, L"start_child_process: InitializeProcThreadAttributeList1 Error: %d", retval);
        return retval;
    }
    
    lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, AttributeListSize);
    if (lpAttributeList == NULL) {
        LOG_W(LOG_ERROR, L"start_child_process: HeapAlloc failed");
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    
    StartupInfoEx.lpAttributeList = lpAttributeList;
    
    if (InitializeProcThreadAttributeList(lpAttributeList, 1, 0, &AttributeListSize) == FALSE) {
        retval = GetLastError();
        LOG_W(LOG_ERROR, L"start_child_process: InitializeProcThreadAttributeList2 Error: %d", retval);
        goto cleanup;
    }

    // Set ProtectionLevel to be the same, i.e. PPL
    if (UpdateProcThreadAttribute(lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
        &ProtectionLevel,
        sizeof(ProtectionLevel),
        NULL,
        NULL) == FALSE)
    {
        retval = GetLastError();
        LOG_W(LOG_ERROR, L"start_child_process: UpdateProcThreadAttribute Error: %d", retval);
        goto cleanup;
    }

    // Start Process (hopefully)
    LOG_W(LOG_INFO, L"start_child_process: Creating Process: '%s'", childCMD);
    if (CreateProcess(NULL,
        childCMD,
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
            LOG_W(LOG_ERROR, L"start_child_process: CreateProcess Error: Invalid Certificate");
        }
        else {
            LOG_W(LOG_ERROR, L"start_child_process: CreateProcess Error: %d", retval);
        }
        goto cleanup;
    }

    // Close handles immediately as we don't need to wait for the process
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(ProcessInformation.hThread);
    
    LOG_W(LOG_INFO, L"start_child_process: Process created successfully");

cleanup:
    // Clean up attribute list
    if (lpAttributeList != NULL) {
        DeleteProcThreadAttributeList(lpAttributeList);
        HeapFree(GetProcessHeap(), 0, lpAttributeList);
    }
    
    LOG_W(LOG_INFO, L"start_child_process: finished with return code %d", retval);
    return retval;
}
