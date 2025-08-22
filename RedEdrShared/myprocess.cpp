#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <tlhelp32.h>

#include "myprocess.h"
#include "utils.h"
#include "../Shared/common.h"

// The implementation is in each solution
void LOG_W(int verbosity, const wchar_t* format, ...);
void LOG_A(int verbosity, const char* format, ...);


// Helper function to get process name by PID using CreateToolhelp32Snapshot
std::wstring GetProcessNameByPid(DWORD pid) {
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
bool ProcessMatchesAnyTarget(const std::string& processName, const std::vector<std::string>& targetNames) {
    for (const auto& target : targetNames) {
        if (contains_case_insensitive(processName, target)) {
            return true;
        }
    }
    return false;
}

// This should be fast
Process* MakeProcess(DWORD pid, std::vector<std::string> targetNames) {
    Process* process;
    process = new Process(pid);

    // Process name
    std::wstring processName = GetProcessNameByPid(pid);
    if (processName.empty()) {
        LOG_A(LOG_WARNING, "MakeProcess: Could not get process name for pid %lu", pid);
		processName = L"<unknown>";
	}
    process->commandline = wstring2string(processName);
    process->name = process->commandline;

    // Check if we should trace
    bool shouldObserve = ProcessMatchesAnyTarget(process->name, targetNames);
    if (shouldObserve) {
        LOG_A(LOG_INFO, "MakeProcess: observe pid %lu: %s", pid, process->name.c_str());
        process->observe = 1;
    }
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

