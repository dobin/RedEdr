#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <string>
#include <vector>
#include <winternl.h>
#include <cwchar>
#include <wchar.h>
#include <psapi.h>
#include <tchar.h>
#include <tlhelp32.h>

#include "config.h"
#include "process.h"
#include "logging.h"

// This should be fast
Process* MakeProcess(DWORD pid, LPCWSTR target_name) {
    Process* process;
    HANDLE hProcess;
    WCHAR exePath[MAX_PATH];

    process = 
        new Process(pid);

    if (target_name == NULL) {
        return process;
    }

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        // We dont care
        //LOG_W(LOG_INFO, L"Could not open process %lu error %lu\n", pid, GetLastError());
        return process;
    }
    if (GetModuleFileNameEx(hProcess, NULL, exePath, MAX_PATH)) {
        if (g_config.debug) {
            LOG_W(LOG_INFO, L"Check new process with name: %s", exePath);
        }
        wchar_t* result = wcsstr(exePath, target_name);
        if (result) {
            LOG_W(LOG_INFO, L"Objcache: observe process %lu executable path: %s", pid, exePath);
            process->observe = 1;
        }
    }
    CloseHandle(hProcess);

    return process;
}


Process::Process() {
    observe = FALSE;
}


Process::Process(DWORD _id) {
    id = _id;
    observe = FALSE;
}


void Process::display() const {
    wprintf(L"PID: %i  parent: %i  observe: %i\n", id, parent_pid, observe);
    wprintf(L"         ImagePath: %ls\n", image_path.c_str());
    wprintf(L"         commandline: %ls\n", commandline.c_str());
    wprintf(L"         working_dir: %ls\n", working_dir.c_str());

    wprintf(L"         is_debugged: %d\n", is_debugged);
    wprintf(L"         is_protected_process: %d\n", is_protected_process);
    wprintf(L"         is_protected_process_light: %d\n", is_protected_process_light);
    wprintf(L"         image_base: 0x%p\n", image_base);
}


wchar_t* Process::serialize() const {
    // Calculate the total size needed for the serialized string
    size_t totalSize = 0;
    totalSize += std::to_wstring(id).length() + 1; // For id
    totalSize += std::to_wstring(parent_pid).length() + 1; // For parent_pid
    totalSize += 1; // For observe
    totalSize += image_path.length() + 1;
    totalSize += commandline.length() + 1;
    totalSize += working_dir.length() + 1;

    // Allocate memory for the serialized string
    wchar_t* serializedString = (wchar_t*)malloc((totalSize + 1) * sizeof(wchar_t));
    if (!serializedString) {
        return nullptr; // Allocation failed
    }

    // Copy the data into the serialized string
    swprintf(serializedString, totalSize + 1, L"%u;%u;%d;%ls;%ls;%ls", id, parent_pid, observe, image_path.c_str(), commandline.c_str(), working_dir.c_str());

    return serializedString;
}


BOOL Process::doObserve() {
    return observe;
}

