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

#include "logging.h"
#include "config.h"
#include "processinfo.h"
#include "utils.h"

#include "mypeb.h"
#include "eventproducer.h"
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
    std::vector<wchar_t> uni(u->Length);
    if (!ReadProcessMemory(hProcess, u->Buffer, uni.data(), u->Length, NULL)) {
        LOG_A(LOG_ERROR, "Procinfo: Could not ReadProcessMemory error: %d", GetLastError());
    }
    else {
        s.assign(uni.begin(), uni.end());
    }
    return s;
}


// Unused, produces a lot of data
bool QueryMemoryRegions(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = 0;
    SIZE_T returnLength = 0;
    char buf[2048];

    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (hNtDll == NULL) {
        LOG_A(LOG_ERROR, "Procinfo: could not find ntdll.dll");
        return FALSE;
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
        c += (int) strlen(buf);
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
    DWORD parentPid = reinterpret_cast<DWORD>(pbi.Reserved3); // InheritedFromUniqueProcessId lol
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
    process->commandline = ReplaceAll(process->commandline, L"\"", L"\\\"");
    process->image_path = GetRemoteUnicodeStr(hProcess, &procParams.ImagePathName);
    process->working_dir = GetRemoteUnicodeStr(hProcess, &procParams.CurrentDirectory.DosPath);
    
    // No need for these for now
    //std::wstring DllPath = my_get_str(hProcess, &procParams.DllPath);
    //std::wstring WindowTitle = my_get_str(hProcess, &procParams.WindowTitle);

    return TRUE;
}


BOOL PrintLoadedModules(DWORD pid, Process* process) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        // We dont care
        LOG_W(LOG_INFO, L"Could not open process %lu error %lu\n", pid, GetLastError());
        return FALSE;
    }

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

    // Read the PEB_LDR_DATA
    PEB_LDR_DATA ldr;
    if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), NULL)) {
        printf("Procinfo: ReadProcessMemory failed for PEB_LDR_DATA\n");
        return FALSE;
    }
    
    // Iterate over the InMemoryOrderModuleList
    LIST_ENTRY* head = &ldr.InMemoryOrderModuleList;
    LIST_ENTRY* current = ldr.InMemoryOrderModuleList.Flink;
    std::wstring csv;
    while (current != head) {
        _LDR_DATA_TABLE_ENTRY entry;
        if (!ReadProcessMemory(hProcess, CONTAINING_RECORD(current, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
            &entry, sizeof(_LDR_DATA_TABLE_ENTRY), NULL))
        {
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
        fullDllName[entry.FullDllName.Length / sizeof(WCHAR)] = L'\0';  // Null-terminate the string

        csv += format_wstring(L"{addr:0x%x;size:0x%x;name:%ls},",
            entry.DllBase,
            (ULONG)entry.Reserved3[1],
            fullDllName);

        // Move to the next module in the list
        current = entry.InMemoryOrderLinks.Flink;
    }

    std::wstring o = format_wstring(L"type:loaded_dll;time:%lld;pid:%lld;dlls:[%s]",
        get_time(),
        process->id,
        csv.c_str()
    );
    remove_all_occurrences_case_insensitive(o, std::wstring(L"C:\\Windows\\system32\\"));
    g_EventProducer.do_output(o);
    return TRUE;
}


Process* MakeProcess(DWORD pid, LPCWSTR target_name) {
    Process* process = new Process(pid);

    HANDLE hProcess;
    WCHAR exePath[MAX_PATH];

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        // We dont care
        LOG_W(LOG_INFO, L"Could not open process %lu error %lu\n", pid, GetLastError());
    }
    else {
        if (target_name != NULL) {
            if (GetModuleFileNameEx(hProcess, NULL, exePath, MAX_PATH)) {
                wchar_t* result = wcsstr(exePath, target_name);
                if (result) {
                    LOG_W(LOG_INFO, L"Objcache: observe process %lu executable path: %s", pid, exePath);
                    //LOG_W(LOG_INFO, L"Substring found in: %s\n", exePath);
                    process->observe = 1;
                }
                else {
                    LOG_W(LOG_INFO, L"Substring not found %lu: %s\n", pid, exePath);
                    process->observe = 0;
                }
            }
            else {
                //LOG_W(LOG_INFO, L"Failed to get executable path: %lu\n", GetLastError());
            }
        }
        CloseHandle(hProcess);
    }
    
    return process;
}


BOOL AugmentProcess(DWORD pid, Process *process) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        //LOG_A(LOG_WARNING, "Could not open process pid: %lu error %lu", pid, GetLastError());
        return FALSE;
    }

    RetrieveProcessInfo(process, hProcess);
    // FIXME check return value?

    /*
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
    */
    CloseHandle(hProcess);
    return TRUE;
}


DWORD FindProcessIdByName(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, processName.c_str())) {
                processId = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return processId;
}
