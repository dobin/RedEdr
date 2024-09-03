#include <stdio.h>
#include <windows.h>
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
#include <stdio.h>
#include <vector>
#include <winternl.h>

#include "loguru.hpp"
#include "config.h"
#include "procinfo.h"
#include "cache.h"
#include "dllinjector.h"
#include "mypeb.h"
#include "output.h"
#include "../Shared/common.h"

#pragma comment(lib, "ntdll.lib")


typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);


// FIXME copy from dll
LARGE_INTEGER get_time() {
    FILETIME fileTime;
    LARGE_INTEGER largeInt;

    // Get the current system time as FILETIME
    GetSystemTimeAsFileTime(&fileTime);

    // Convert FILETIME to LARGE_INTEGER
    largeInt.LowPart = fileTime.dwLowDateTime;
    largeInt.HighPart = fileTime.dwHighDateTime;

    return largeInt;
}


// Gets a UNICODE_STRING content in a remote process as wstring
std::wstring my_get_str(HANDLE hProcess, UNICODE_STRING* u) {
    std::wstring s;
    std::vector<wchar_t> commandLine(u->Length / sizeof(wchar_t));
    if (!ReadProcessMemory(hProcess, u->Buffer, commandLine.data(), u->Length, NULL)) {
        LOG_F(ERROR, "Error: Could not ReadProcessMemory error: %d", GetLastError());
    }
    else {
        s.assign(commandLine.begin(), commandLine.end());
    }
    return s;
}


bool augment_process_info(Process *process, HANDLE hProcess) {
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        LOG_F(ERROR, "Error: Could not get NtQueryInformationProcess error: %d", GetLastError());
        return FALSE;
    }
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        LOG_F(ERROR, "Error: Could not NtQueryInformationProcess for %d, error: %d", status, GetLastError());
        return FALSE;
    }

    DWORD parentPid = (DWORD)pbi.Reserved3; // InheritedFromUniqueProcessId lol
    process->parent_pid = parentPid;

    MYPEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        // this is the first read, and may fail. 
        // dont spam log messages
        LOG_F(WARNING, "Error: Could not ReadProcessMemory1 for error: %d", GetLastError());
        return FALSE;
    }

    // PEB directly accessible
    /*
    printf("InheritedAddressSpace: %i\n", peb.InheritedAddressSpace);
    printf("ReadImageFileExecOptions: %i\n", peb.ReadImageFileExecOptions);
    printf("BeingDebugged : %i\n", peb.BeingDebugged);
    printf("IsProtectedProcess : %i\n", peb.IsProtectedProcess);
    printf("IsImageDynamicallyRelocated : %i\n", peb.IsImageDynamicallyRelocated);
    printf("IsAppContainer : %i\n", peb.IsAppContainer);
    printf("IsProtectedProcessLight : %i\n", peb.IsProtectedProcessLight);
    printf("ImageBaseAddress: 0x%p\n", peb.ImageBaseAddress);
    printf("ProcessUsingVEH: %i\n", peb.ProcessUsingVEH);
    printf("pImageHeaderHash: 0x%p\n", peb.pImageHeaderHash);
    */
    process->is_debugged = peb.BeingDebugged;
    process->is_protected_process = peb.IsProtectedProcess;
    process->is_protected_process_light = peb.IsProtectedProcessLight;
    process->image_base = peb.ImageBaseAddress;

    // ProcessParameters - anoying copying
    MY_RTL_USER_PROCESS_PARAMETERS procParams;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), NULL)) {
        LOG_F(ERROR, "Error: Could not ReadProcessMemory for %d, error: %d", process->id, GetLastError());
        return FALSE;
    }
    process->commandline = my_get_str(hProcess, &procParams.CommandLine);
    process->image_path = my_get_str(hProcess, &procParams.ImagePathName);
    process->working_dir = my_get_str(hProcess, &procParams.CurrentDirectory.DosPath);
    
    // No need for these for now
    //std::wstring DllPath = my_get_str(hProcess, &procParams.DllPath);
    //std::wstring WindowTitle = my_get_str(hProcess, &procParams.WindowTitle);

    // Ldr
    // DLL's ?
}


std::wstring format_wstring(const wchar_t* format, ...) {
    wchar_t buffer[DATA_BUFFER_SIZE];

    va_list args;
    va_start(args, format);
    vswprintf(buffer, DATA_BUFFER_SIZE, format, args);
    va_end(args);

    return std::wstring(buffer);
}


Process* MakeProcess(DWORD pid) {
    Process* process = new Process(pid);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        //LOG_F(WARNING, "Could not open process pid: %lu error %lu", pid, GetLastError());
        return process;
    }

    augment_process_info(process, hProcess);
    //return process;

    // CHECK: Observe
    BOOL observe = FALSE;
    //if (wcsstr(process->image_path.c_str(), (LPCWSTR)g_config.targetExeName)) {
    if (process->image_path.find(g_config.targetExeName) != std::wstring::npos) {
        // CHECK: Process name
        LOG_F(INFO, "Observe CMD: %d %ls", pid, process->image_path.c_str());
        observe = TRUE;
    } else if (g_cache.containsObject(process->parent_pid)) { // dont recursively resolve all
        // CHECK: Parent observed?
        if (g_cache.getObject(process->parent_pid)->doObserve()) {
            LOG_F(INFO, "Observe PID: %d (because PPID %d): %ls", pid, process->parent_pid, process->image_path.c_str());
            observe = TRUE;
        }
    }
    else {
        //LOG_F(INFO, "Dont observe: %ls because %ls", process->image_path.c_str(), g_config.targetExeName);
    }
    process->observe = observe;

    // every new pid comes through here
    // if everything worked
    // if we observe it, we need to DLL inject it too
    if (observe && g_config.do_udllinjection) {
        remote_inject(pid);
    }

    if (observe) {
        std::wstring o = format_wstring(L"type:peb;time:%lld;id:%lld;parent_pid:%lld;image_path:%ls;commandline:%ls;working_dir:%ls;is_debugged:%d;is_protected_process:%d;is_protected_process_light:%d;image_base:0x%p",
            get_time(),
            process->id,
            process->parent_pid,
            process->image_path,
            process->commandline,
            process->working_dir,
            process->is_debugged,
            process->is_protected_process,
            process->is_protected_process_light,
            process->image_base
            );
        do_output(o);
    }

    CloseHandle(hProcess);
    return process;
}
