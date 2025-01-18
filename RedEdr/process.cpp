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
#include "utils.h"


// This should be fast
Process* MakeProcess(DWORD pid, std::string targetName) {
    Process* process;

    process = new Process(pid);
    process->OpenTarget();

    // Process name
    std::wstring processName = GetProcessName(process->GetHandle());
    if (g_Config.debug) {
        LOG_W(LOG_INFO, L"Process: Check new process with name: %s", processName.c_str());
    }
    process->commandline = wstring2string(processName);

    // Check if we should trace
    if (contains_case_insensitive(process->commandline, targetName)) {
        LOG_A(LOG_INFO, "Process: observe pid %lu: %s", pid, process->commandline.c_str());
        process->observe = 1;
    }
    else {
        if (g_Config.debug) {
            LOG_W(LOG_INFO, L"Process: DONT observe pid %lu: %s", pid, process->commandline.c_str());
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

