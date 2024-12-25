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
#include "process_query.h"


// This should be fast
Process* MakeProcess(DWORD pid, LPCWSTR target_name) {
    Process* process;

    process = new Process(pid);
    if (target_name == NULL) {
        return process;
    }
    process->OpenTarget();

    std::wstring processName = GetProcessName(process->GetHandle());
    if (g_config.debug) {
        LOG_W(LOG_INFO, L"Check new process with name: %s", processName.c_str());
    }
    process->commandline = processName;

    wchar_t* result = wcsstr((wchar_t*) processName.c_str(), target_name);
    if (result) {
        LOG_W(LOG_INFO, L"Objcache: observe process %lu executable path: %s", pid, processName.c_str());
        process->observe = 1;
    }
    else {
        if (g_config.debug) {
            LOG_W(LOG_INFO, L"Objcache: DONT observe: %s %s", pid, processName.c_str(), target_name);
        }
        // If we dont observe, we dont need to keep the handle open, as no further
        // queries are gonna be made
        process->CloseTarget();
    }
    return process;
}


BOOL Process::OpenTarget() {
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, id);
    if (!hProcess) {
        //LOG_A(LOG_WARNING, "Could not open process pid: %lu error %lu", pid, GetLastError());
        return FALSE;
    }
    return TRUE;
}


BOOL Process::CloseTarget() {
    CloseHandle(hProcess);
    hProcess = NULL;
    return TRUE;
}


HANDLE Process::GetHandle() {
    return hProcess;
}


Process::Process() {
    observe = FALSE;
}


Process::Process(DWORD _id) {
    id = _id;
    observe = FALSE;
}


BOOL Process::doObserve() {
    return observe;
}

