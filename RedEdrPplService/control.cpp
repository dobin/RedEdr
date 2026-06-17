#include <Windows.h>
#include <iostream>
#include <filesystem>

#include "control.h"
#include "emitter.h"
#include "../Shared/common.h"
#include "logging.h"
#include "etwtireader.h"
#include "etwtihandler.h"
#include "piping.h"
#include "json.hpp"
#include "process_resolver.h"
#include "../RedEdrShared/utils.h"


namespace fs = std::filesystem;

// Link against Version.lib
#pragma comment(lib, "Version.lib")

DWORD start_child_process(wchar_t* childCMD);


HANDLE control_thread = NULL;
volatile BOOL keep_running = TRUE; // Made volatile for thread safety

PipeServer pipeServer = PipeServer("RedEdrPPL Server", (wchar_t*)PPL_SERVICE_PIPE_NAME);


// Helper function to extract file version (of a PE/dll)
std::string GetDllVersion(const fs::path& dllPath) {
    DWORD dwHandle = 0;
    DWORD dwSize = GetFileVersionInfoSizeW(dllPath.c_str(), &dwHandle);
    
    if (dwSize == 0) return "Unknown";

    std::vector<BYTE> buffer(dwSize);
    if (!GetFileVersionInfoW(dllPath.c_str(), 0, dwSize, buffer.data())) {
        return "Unknown";
    }

    VS_FIXEDFILEINFO* lpFileInfo = nullptr;
    UINT uiLen = 0;
    if (!VerQueryValueW(buffer.data(), L"\\", (LPVOID*)&lpFileInfo, &uiLen) || uiLen == 0) {
        return "Unknown";
    }

    // Extract major, minor, build, and private parts
    int major = HIWORD(lpFileInfo->dwFileVersionMS);
    int minor = LOWORD(lpFileInfo->dwFileVersionMS);
    int build = HIWORD(lpFileInfo->dwFileVersionLS);
    int revision = LOWORD(lpFileInfo->dwFileVersionLS);

    return std::to_string(major) + "." + 
           std::to_string(minor) + "." + 
           std::to_string(build) + "." + 
           std::to_string(revision);
}


std::string GetMpengineVersion() {
    fs::path baseDir = L"C:\\ProgramData\\Microsoft\\Windows Defender\\Definition Updates";
    fs::path targetDll;

    // 1. Search dynamically for mpengine.dll inside subdirectories
    // Its in something like: 
    // C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{26187561-F935-4D14-8C5C-78828BFBE0F6}\mpengine.dll
    if (fs::exists(baseDir) && fs::is_directory(baseDir)) {
        for (const auto& entry : fs::recursive_directory_iterator(baseDir)) {
            if (entry.is_regular_file() && entry.path().filename() == "mpengine.dll") {
                targetDll = entry.path();
                break; // Found the active instance
            }
        }
    }

    // 2. Return the found version
    if (!targetDll.empty()) {
        LOG_W(LOG_INFO, L"Found mpengine.dll at: %s", targetDll.c_str());
        return GetDllVersion(targetDll);
    } else {
        LOG_A(LOG_WARNING, "mpengine.dll could not be found under the Definition Updates tree.");
        return "Unknown";
    }
}


nlohmann::json GetDefenderPlatformInfo() {
    nlohmann::json info;
    
    // Helper lambda to read registry string and convert to narrow string
    auto readRegString = [](const std::wstring& subKey, const std::wstring& valueName) -> std::string {
        HKEY hKey;
        wchar_t buffer[MAX_PATH];
        DWORD bufferSize = sizeof(buffer);

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExW(hKey, valueName.c_str(), NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return wchar2string(buffer);
            }
            RegCloseKey(hKey);
        }
        return "";
    };

    info["as_signature_version"] = readRegString(L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates", L"ASSignatureVersion");
    info["av_signature_version"] = readRegString(L"SOFTWARE\\Microsoft\\Windows Defender\\Signature Updates", L"AVSignatureVersion");
    info["install_location"] = readRegString(L"SOFTWARE\\Microsoft\\Windows Defender", L"InstallLocation");
    
    return info;
}


void SendDefenderInfos() {
    // Emit defender trace start event with MsMpEng.exe module info (DLL list) and engine version
    DWORD pid = FindProcessIdByName(L"MsMpEng.exe");
    if (pid != 0) {
        Process* process = g_ProcessResolver.getObject(pid);
        if (process) {
            LOG_A(LOG_INFO, "Control: Found MsMpEng.exe (PID: %lu) in resolver", pid);
            
            // Augment process info if not already done
            if (!process->augmented) {
                if (process->AugmentInfo()) {
                    process->augmented = TRUE;
                } else {
                    LOG_A(LOG_ERROR, "Control: Failed to augment MsMpEng.exe process info");
                }
            }
            
            nlohmann::json modules_array = nlohmann::json::array();
            for (const auto& mod : process->processLoadedDlls) {
                nlohmann::json mod_info;

                // Keep full path, but extract just the filename if it's in system32 to save space
                std::string mod_name = mod.name;
                
                // Case-insensitive check for "system32\"
                std::string lower_name = mod_name;
                for (char& c : lower_name) {
                    if (c >= 'A' && c <= 'Z') c += 32;
                }
                
                if (lower_name.find("system32\\") != std::string::npos) {
                    size_t pos = mod_name.find_last_of("\\/");
                    if (pos != std::string::npos) {
                        mod_name = mod_name.substr(pos + 1);
                    }
                }

                mod_info["name"] = mod_name;
                mod_info["base"] = mod.dll_base;
                mod_info["size"] = mod.size;
                modules_array.push_back(mod_info);
                
                //LOG_A(LOG_INFO, "Control: MsMpEng.exe module: %s at 0x%llx (size: %lu)", mod.name.c_str(), mod.dll_base, mod.size);
            }
            
            // Send single event with all modules and engine version
            nlohmann::json defender_event;
            defender_event["event"] = "defender_modules";
            defender_event["type"] = "meta";
            defender_event["pid"] = pid;
            defender_event["modules"] = modules_array;
            defender_event["mpengine_version"] = GetMpengineVersion();
            SendEmitterPipe((char*)defender_event.dump().c_str());

            // Send separate event with platform info
            nlohmann::json platform_event;
            platform_event["event"] = "defender_platform_info";
            platform_event["type"] = "meta";
            platform_event["pid"] = pid;
            nlohmann::json platform_info = GetDefenderPlatformInfo();
            platform_event["as_signature_version"] = platform_info["as_signature_version"];
            platform_event["av_signature_version"] = platform_info["av_signature_version"];
            platform_event["install_location"] = platform_info["install_location"];
            SendEmitterPipe((char*)platform_event.dump().c_str());
        } else {
            LOG_A(LOG_ERROR, "Control: Failed to get MsMpEng.exe process from resolver");
        }
    } else {
        LOG_A(LOG_WARNING, "Control: msmpeng.exe process not found");
    }
}


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
                            g_ProcessResolver.SetTargetNames(targets);
                            g_ProcessResolver.RefreshTargetMatching();

                            BOOL doDefenderTrace = j.value("do_defendertrace", false) ? TRUE : FALSE;
                            SetDefenderTraceConfig(doDefenderTrace);

                            if (doDefenderTrace) {
                                // Send on each new start command
                                SendDefenderInfos();
                            }
                        } else {
                            LOG_A(LOG_ERROR, "Control: Start command missing 'targets' array");
                        }
                    }
                    else if (command == "stop") {
                        nlohmann::json stop_event;
                        stop_event["event"] = "ppl_stop";
                        stop_event["type"] = "meta";
                        SendEmitterPipe((char*) stop_event.dump().c_str());
                    } else if (command == "shutdown") {
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
