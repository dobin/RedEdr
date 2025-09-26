#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <tlhelp32.h>

#include "myprocess.h"
#include "utils.h"
#include "process_query.h"
#include "../Shared/common.h"

// The implementation is in each solution
void LOG_W(int verbosity, const wchar_t* format, ...);
void LOG_A(int verbosity, const char* format, ...);


// Helper function to get process command line by PID
// Falls back to process name if command line cannot be retrieved
std::wstring GetProcessNameByPid(DWORD pid) {
    // First try to get the full command line by opening the process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess != NULL) {
        try {
            ProcessPebInfoRet pebInfo = ProcessPebInfo(hProcess);
            CloseHandle(hProcess);
            if (!pebInfo.commandline.empty()) {
                return string2wstring(pebInfo.commandline);
            }
        }
        catch (const std::exception& e) {
            //LOG_A(LOG_WARNING, "GetProcessNameByPid: Exception getting PEB info for pid %lu: %s", pid, e.what());
            CloseHandle(hProcess);
        }
    //} else {
    //    LOG_A(LOG_WARNING, "GetProcessNameByPid: Could not open process %lu for command line query (error %lu), falling back to process name", pid, GetLastError());
    }
    
    // Fallback: use CreateToolhelp32Snapshot to get just the process name
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "GetProcessNameByPid: Failed to create process snapshot: %lu", GetLastError());
        return std::wstring(L"");
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    // Get the first process
    if (!Process32FirstW(hSnapshot, &pe32)) {
        LOG_A(LOG_ERROR, "GetProcessNameByPid: Failed to get first process: %lu", GetLastError());
        CloseHandle(hSnapshot);
        return std::wstring(L"");
    }
    
    std::wstring processName;
    do {
        if (pe32.th32ProcessID == pid) {
            processName = std::wstring(pe32.szExeFile);
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    return processName;
}


// Helper function to check if process name matches any target
bool Process::ObserveIfMatchesTargets(const std::vector<std::string>& targetNames) {
    for (const auto& target : targetNames) {
        if (contains_case_insensitive(name, target)) {
            LOG_A(LOG_INFO, "Process: observe pid %lu: %s", id, name.c_str());
            observe = TRUE;
            return true;
        }
    }
    observe = FALSE;
    return false;
}


bool Process::AugmentInfo() {
    if (!OpenTarget()) {
        LOG_A(LOG_WARNING, "EventProcessor: Cannot open process handle for pid %lu", id);
        return FALSE;
    }
    
    // Check if it is still running
    DWORD exitCode;
    if (!GetExitCodeProcess(GetHandle(), &exitCode)) {
        LOG_A(LOG_WARNING, "EventProcessor: Failed to get exit code for process pid %lu, error: %lu",
            id, GetLastError());
        CloseTarget();
        return FALSE;
    }
    if (exitCode != STILL_ACTIVE) {
        LOG_A(LOG_WARNING, "EventProcessor: Process pid %lu is not active (exit code: %lu)",
            id, exitCode);
        CloseTarget();
        return FALSE;
    }

    // PEB info
    processPebInfoRet = ProcessPebInfo(GetHandle());

    // Loaded modules
    processLoadedDlls = ProcessEnumerateModules(GetHandle());
    for (auto processLoadedDll : processLoadedDlls) {
        try {
            std::vector<ModuleSection> moduleSections = EnumerateModuleSections(
                GetHandle(), 
                uint64_to_pointer(processLoadedDll.dll_base));
            for (auto moduleSection : moduleSections) {
                MemoryRegion* memoryRegion = new MemoryRegion(
                    moduleSection.name,
                    moduleSection.addr, 
                    moduleSection.size, 
                    moduleSection.protection);
                memStatic.AddMemoryRegion(memoryRegion->addr, memoryRegion);
            }
        }
        catch (const std::exception& e) {
            LOG_A(LOG_ERROR, "EventProcessor: Error enumerating sections for module %s: %s", 
                    processLoadedDll.name.c_str(), e.what());
        }
    }

    CloseTarget();
    return TRUE;
}


// This should be fast
Process* MakeProcess(DWORD pid, std::vector<std::string> targetNames) {
    Process* process;
    process = new Process(pid);

    // Process name/command line
    std::wstring processName = GetProcessNameByPid(pid);
    if (processName.empty()) {
        //LOG_A(LOG_WARNING, "MakeProcess: Could not get process name for pid %lu", pid);
		processName = L"<unknown>";
    }
    process->commandline = wstring2string(processName);
    process->name = process->commandline;

    // Dont observe ourselves
    if (contains_case_insensitive(process->name, "rededr.exe")) {
        process->observe = 0;
        return process;
    }

    // Check if we should trace
    process->ObserveIfMatchesTargets(targetNames);

    return process;
}


BOOL Process::OpenTarget() {
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, id);
    if (!hProcess) {
        LOG_A(LOG_WARNING, "Could not open process pid: %lu error %lu", id, GetLastError());
        return FALSE;
    }
    return TRUE;
}


BOOL Process::CloseTarget() {
    if (hProcess != NULL) {
        CloseHandle(hProcess);
        hProcess = NULL;
    }
    return TRUE;
}


HANDLE Process::GetHandle() {
    return hProcess;
}


Process::Process() {
    observe = FALSE;
    hProcess = NULL;
}


Process::Process(DWORD _id) {
    id = _id;
    observe = FALSE;
    hProcess = NULL;
}


BOOL Process::doObserve() {
    return observe;
}

