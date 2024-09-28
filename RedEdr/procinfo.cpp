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

#include "logging.h"
#include "config.h"
#include "procinfo.h"
#include "cache.h"
#include "dllinjector.h"
#include "mypeb.h"
#include "output.h"
#include "utils.h"
#include "../Shared/common.h"

#pragma comment(lib, "ntdll.lib")


typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);

typedef NTSTATUS(NTAPI* pNtQueryVirtualMemory)(
    HANDLE                   ProcessHandle,
    PVOID                    BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID                    MemoryInformation,
    SIZE_T                   MemoryInformationLength,
    PSIZE_T                  ReturnLength
);


// Gets a UNICODE_STRING content in a remote process as wstring
std::wstring GetRemoteUnicodeStr(HANDLE hProcess, UNICODE_STRING* u) {
    std::wstring s;
    //std::vector<wchar_t> commandLine(u->Length / sizeof(wchar_t));
    std::vector<wchar_t> commandLine(u->Length);
    if (!ReadProcessMemory(hProcess, u->Buffer, commandLine.data(), u->Length, NULL)) {
        LOG_A(LOG_ERROR, "Procinfo: Could not ReadProcessMemory error: %d", GetLastError());
    }
    else {
        s.assign(commandLine.begin(), commandLine.end());
    }
    return s;
}


// Unused, produces a lot of data
bool QueryMemoryRegions(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = 0;
    SIZE_T returnLength = 0;
    char buf[2048];
    PROCESS_BASIC_INFORMATION pbi;
    NTSTATUS status;

    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (hNtDll == NULL) {
        LOG_A(LOG_ERROR, "Procinfo: could not find ntdll.dll");
    }

    pNtQueryVirtualMemory NtQueryVirtualMemory = (pNtQueryVirtualMemory)GetProcAddress(hNtDll, "NtQueryVirtualMemory");
    if (NtQueryInformationProcess == NULL) {
        LOG_A(LOG_ERROR, "Procinfo: Could not get NtQueryVirtualMemory error: %d", GetLastError());
        return FALSE;
    }
    int c = 0, cc = 0;
    while (NtQueryVirtualMemory(hProcess, address, MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength) == 0) {
        if (mbi.Type == 0 || mbi.Protect == 0 || mbi.State != MEM_COMMIT) {
            address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
            continue;
        }
        // skip IMAGE regions
        //if (mbi.Type == MEM_IMAGE) {
        if (mbi.Type != MEM_PRIVATE) {
            address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
            continue;
        }
        
        //printf("addr:%p;size:%zu;state:0x%lx;protect:0x%lx;type:0x%lx\n",
        //    mbi.BaseAddress, mbi.RegionSize, mbi.State, mbi.Protect, mbi.Type);

        //printf("addr:%p;size:%zu;protect:0x%lx;type:0x%lx\n",
        //    mbi.BaseAddress, mbi.RegionSize, mbi.Protect, mbi.Type);

        sprintf_s(buf, sizeof(buf), "addr:%p;size:%zu;protect:0x%lx;",
            mbi.BaseAddress, mbi.RegionSize, mbi.Protect);
        c += strlen(buf);
        cc += 1;
        printf("%s\n", buf);

        //printf("Protection: ");
        //PrintProtectionFlags(mbi.Protect);
        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    printf("Len bytes: %i   lines: %i\n", c, cc);

    return TRUE;
}


bool RetrieveProcessInfo(Process *process, HANDLE hProcess) {
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (hNtDll == NULL) {
        LOG_A(LOG_ERROR, "Procinfo: could not find ntdll.dll");
        return FALSE;
    }
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        LOG_A(LOG_ERROR, "Procinfo: Error: Could not get NtQueryInformationProcess error: %d", GetLastError());
        return FALSE;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        LOG_A(LOG_ERROR, "Procinfo: Error: Could not NtQueryInformationProcess for %d, error: %d", status, GetLastError());
        return FALSE;
    }

    // PBI follows
    DWORD parentPid = (DWORD)pbi.Reserved3; // InheritedFromUniqueProcessId lol
    process->parent_pid = parentPid;

    // PEB follows
    MYPEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        // this is the first read, and may fail. 
        // dont spam log messages
        //LOG_A(LOG_WARNING, "Error: Could not ReadProcessMemory1 for process %d error: %d", 
        //    process->id, GetLastError());
        process->PebBaseAddress = pbi.PebBaseAddress;
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
        LOG_A(LOG_ERROR, "Error: Could not ReadProcessMemory for %d, error: %d", process->id, GetLastError());
        return FALSE;
    }
    process->commandline = GetRemoteUnicodeStr(hProcess, &procParams.CommandLine);
    process->image_path = GetRemoteUnicodeStr(hProcess, &procParams.ImagePathName);
    process->working_dir = GetRemoteUnicodeStr(hProcess, &procParams.CurrentDirectory.DosPath);
    
    // No need for these for now
    //std::wstring DllPath = my_get_str(hProcess, &procParams.DllPath);
    //std::wstring WindowTitle = my_get_str(hProcess, &procParams.WindowTitle);

    return TRUE;
}


BOOL PrintLoadedModules(HANDLE hProcess, Process* process) {
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (hNtDll == NULL) {
        LOG_A(LOG_ERROR, "Procinfo: could not find ntdll.dll");
        return FALSE;
    }
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        LOG_A(LOG_ERROR, "Procinfo: Error: Could not get NtQueryInformationProcess error: %d", GetLastError());
        return FALSE;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        LOG_A(LOG_ERROR, "Procinfo: Error: Could not NtQueryInformationProcess for %d, error: %d", status, GetLastError());
        return FALSE;
    }

    // PEB follows
    MYPEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        // this is the first read, and may fail. 
        // dont spam log messages
        //LOG_A(LOG_WARNING, "Error: Could not ReadProcessMemory1 for process %d error: %d", 
        //    process->id, GetLastError());
        process->PebBaseAddress = pbi.PebBaseAddress;
        return FALSE;
    }


    /*
    // Read the PEB_LDR_DATA
    PEB_LDR_DATA ldr;
    if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), NULL)) {
        printf("Procinfo: ReadProcessMemory failed for PEB_LDR_DATA\n");
        return FALSE;
    }
    
    // Iterate over the InMemoryOrderModuleList
    LIST_ENTRY* head = &ldr.InMemoryOrderModuleList;
    LIST_ENTRY* current = ldr.InMemoryOrderModuleList.Flink;
    while (current != head) {
        _LDR_DATA_TABLE_ENTRY entry;
        if (!ReadProcessMemory(hProcess, CONTAINING_RECORD(current, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
            &entry, sizeof(_LDR_DATA_TABLE_ENTRY), NULL)) {
            printf("Procinfo: ReadProcessMemory failed for LDR_DATA_TABLE_ENTRY\n");
            return FALSE;
        }
        if (entry.DllBase == 0) { // all zero is last one for some reason
            break;
        }
        // Print information about the loaded module
        WCHAR fullDllName[MAX_PATH];
        if (!ReadProcessMemory(hProcess, entry.FullDllName.Buffer, fullDllName, entry.FullDllName.Length, NULL)) {
            printf("Procinfo: ReadProcessMemory failed for FullDllName\n");
            return FALSE;
        }
        fullDllName[entry.FullDllName.Length] = L'\0';  // Null-terminate the string

        //printf("Module: %ls, Base: %p, Size: 0x%lx\n", fullDllName, entry.DllBase, (ULONG)entry.Reserved3[1]); //entry.SizeOfImage);
        std::wstring o = format_wstring(L"type:loaded_dll;time:%lld;pid:%lld;name:%ls;addr:0x%x;size:0x%x",
            get_time(),
            process->id,
            fullDllName,
            entry.DllBase,
            (ULONG)entry.Reserved3[1]);
        do_output(o.c_str());

        // Move to the next module in the list
        current = entry.InMemoryOrderLinks.Flink;
    }*/
}


Process* MakeProcess(DWORD pid) {
    Process* process = new Process(pid);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        //LOG_A(LOG_WARNING, "Could not open process pid: %lu error %lu", pid, GetLastError());
        return process;
    }

    RetrieveProcessInfo(process, hProcess);
    // FIXME check return value?

    // CHECK: Observe
    BOOL observe = FALSE;

    //if (wcsstr(process->image_path.c_str(), (LPCWSTR)g_config.targetExeName)) {
    if (process->image_path.find(g_config.targetExeName) != std::wstring::npos) {
        // CHECK: Process name
        LOG_A(LOG_INFO, "Procinfo: Observe CMD: %d %ls", pid, process->image_path.c_str());
        observe = TRUE;
    } else if (g_cache.containsObject(process->parent_pid)) { // dont recursively resolve all
        // CHECK: Parent observed?
        if (g_cache.getObject(process->parent_pid)->doObserve()) {
            LOG_A(LOG_INFO, "Procinfo: Observe PID: %d (because PPID %d): %ls", pid, process->parent_pid, process->image_path.c_str());
            observe = TRUE;
        }
    }
    else {
        //LOG_A(LOG_INFO, "Dont observe: %ls because %ls", process->image_path.c_str(), g_config.targetExeName);
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
            process->image_path.c_str(),
            process->commandline.c_str(),
            process->working_dir.c_str(),
            process->is_debugged,
            process->is_protected_process,
            process->is_protected_process_light,
            process->image_base
            );
        do_output(o);

        PrintLoadedModules(hProcess, process);
    }

    // in RetrieveProcessInfo() atm
    // LogDllFromProcess(hProcess);

    CloseHandle(hProcess);
    return process;
}
