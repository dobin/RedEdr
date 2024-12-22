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
#include "process_query.h"
#include "utils.h"
#include "process.h"

#include "mypeb.h"
#include "event_aggregator.h"
#include "mem_static.h"
#include "../Shared/common.h"

#pragma comment(lib, "ntdll.lib")


// Private
wchar_t* GetFileNameFromPath(wchar_t* path);
BOOL ProcessEnumerateModules(Process* process, HANDLE hProcess);
void EnumerateModuleSections(Process* process, HANDLE hProcess, LPVOID moduleBase);
std::wstring GetRemoteUnicodeStr(HANDLE hProcess, UNICODE_STRING* u);
BOOL ProcessPebInfo(Process* process, HANDLE hProcess);
std::string GetSectionPermissions(DWORD characteristics);


// Some stupid definitions (dont belong in the .h)
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


// Additional low level windows functions
pNtQueryVirtualMemory NtQueryVirtualMemory;


BOOL InitProcessQuery() {
    HMODULE hNtDll;
    hNtDll = GetModuleHandle(L"ntdll.dll");
    if (hNtDll == NULL) {
        LOG_A(LOG_ERROR, "ProcessQuery: could not find ntdll.dll");
        return FALSE;
    }
    NtQueryVirtualMemory = (pNtQueryVirtualMemory)GetProcAddress(hNtDll, "NtQueryVirtualMemory");
    if (NtQueryVirtualMemory == NULL) {
        LOG_A(LOG_ERROR, "ProcessQuery: Could not get NtQueryVirtualMemory error: %d", GetLastError());
        return FALSE;
    }
    return TRUE;
}


BOOL AugmentProcess(DWORD pid, Process* process) {
    LOG_A(LOG_INFO, "ProcessQuery: Augmenting process %lu", pid);
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        //LOG_A(LOG_WARNING, "Could not open process pid: %lu error %lu", pid, GetLastError());
        return FALSE;
    }

    ProcessPebInfo(process, hProcess);
    ProcessEnumerateModules(process, hProcess);
    //QueryMemoryRegions(hProcess);

    CloseHandle(hProcess);
    return TRUE;
}


// Process: PEB Info
BOOL ProcessPebInfo(Process* process, HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;

    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        LOG_A(LOG_ERROR, "Procinfo: Error: Could not NtQueryInformationProcess for %d, error: %d", status, GetLastError());
        return FALSE;
    }

    // PPID
    DWORD parentPid = reinterpret_cast<DWORD>(pbi.Reserved3); // InheritedFromUniqueProcessId lol
    process->parent_pid = parentPid;

    // PEB
    MYPEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        LOG_A(LOG_WARNING, "ProcessQuery: Error: Could not ReadProcessMemory1 for process %d error: %d", 
            process->id, GetLastError());
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
        LOG_A(LOG_ERROR, "ProcessQuery: Error: Could not ReadProcessMemory for %d, error: %d", process->id, GetLastError());
        return FALSE;
    }
    process->commandline = GetRemoteUnicodeStr(hProcess, &procParams.CommandLine);
    //process->commandline = ReplaceAll(process->commandline, L"\"", L"\\\"");
    process->image_path = GetRemoteUnicodeStr(hProcess, &procParams.ImagePathName);
    process->working_dir = GetRemoteUnicodeStr(hProcess, &procParams.CurrentDirectory.DosPath);

    // No need for these for now
    //std::wstring DllPath = my_get_str(hProcess, &procParams.DllPath);
    //std::wstring WindowTitle = my_get_str(hProcess, &procParams.WindowTitle);

    return TRUE;
}


// Enumerate all modules loaded in the process (DLL's), and their sections
BOOL ProcessEnumerateModules(Process* process, HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        LOG_A(LOG_ERROR, "ProcessQuery: Error: Could not NtQueryInformationProcess for %d, error: %d", status, GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // PEB follows
    MYPEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        LOG_A(LOG_WARNING, "ProcessQuery: Error: Could not ReadProcessMemory1 for process %d error: %d", 
            process->id, GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    // Read the PEB_LDR_DATA
    PEB_LDR_DATA ldr;
    if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), NULL)) {
        printf("ProcessQuery:ReadProcessMemory failed for PEB_LDR_DATA\n");
        CloseHandle(hProcess);
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
            printf("ProcessQuery: ReadProcessMemory failed for LDR_DATA_TABLE_ENTRY\n");
            CloseHandle(hProcess);
            return FALSE;
        }
        if (entry.DllBase == 0) { // all zero is last one for some reason
            break;
        }
        // Print information about the loaded module
        WCHAR fullDllName[MAX_PATH] = { 0 };
        if (!ReadProcessMemory(hProcess, entry.FullDllName.Buffer, fullDllName, entry.FullDllName.Length, NULL)) {
            printf("ProcessQuery: ReadProcessMemory failed for FullDllName\n");
            CloseHandle(hProcess);
            return FALSE;
        }
        fullDllName[entry.FullDllName.Length / sizeof(WCHAR)] = L'\0';  // Null-terminate the string

        // Short DLLS summary
        csv += format_wstring(L"{\"addr\":%llu,\"size\":%llu,\"name\":\"%s\"},",
            entry.DllBase,
            (ULONG)entry.Reserved3[1],
            JsonEscape(GetFileNameFromPath(fullDllName), MAX_PATH));

        // Handle the individual sections 
        EnumerateModuleSections(process, hProcess, entry.DllBase);

        // Move to the next module in the list
        current = entry.InMemoryOrderLinks.Flink;
    }

    std::wstring ffff = csv;
    ffff.pop_back(); // remove fucking last comma
    std::wstring o = format_wstring(L"{\"func\":\"loaded_dll\",\"type\":\"process_query\",\"time\":%lld,\"pid\":%lld,\"dlls\":[%s]}",
        get_time(),
        process->id,
        ffff.c_str()
    );
    remove_all_occurrences_case_insensitive(o, std::wstring(L"C:\\\\Windows\\\\system32\\\\"));
    g_EventAggregator.do_output(o);
}


void EnumerateModuleSections(Process* process, HANDLE hProcess, LPVOID moduleBase) {
    // Buffer for headers
    IMAGE_DOS_HEADER dosHeader = {};
    IMAGE_NT_HEADERS ntHeaders = {};
    std::vector<IMAGE_SECTION_HEADER> sectionHeaders;

    // Buffer for module name
    wchar_t moduleName[MAX_PATH] = { 0 };
    if (!GetModuleBaseName(hProcess, (HMODULE)moduleBase, moduleName, sizeof(moduleName))) {
        LOG_A(LOG_WARNING, "ProcessQuery: Failed to retrieve module name. Error: %lu", GetLastError());
        return;
    }
    std::string moduleNameStr = wcharToString(moduleName);

    // Read the DOS header
    if (!ReadProcessMemory(hProcess, moduleBase, &dosHeader, sizeof(dosHeader), NULL)) {
        LOG_A(LOG_WARNING, "ProcessQuery: Failed to read DOS header. Error: %lu", GetLastError());
        return;
    }
    // Verify DOS signature
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        LOG_A(LOG_WARNING, "ProcessQuery: Invalid DOS signature. Not a valid PE file");
        return;
    }
    // Read the NT header
    LPVOID ntHeaderAddress = (LPBYTE)moduleBase + dosHeader.e_lfanew;
    if (!ReadProcessMemory(hProcess, ntHeaderAddress, &ntHeaders, sizeof(ntHeaders), NULL)) {
        LOG_A(LOG_WARNING, "ProcessQuery: Failed to read NT headers. Error: %lu", GetLastError());

        return;
    }
    // Verify NT signature
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        LOG_A(LOG_WARNING, "ProcessQuery: Invalid NT signature. Not a valid PE file.");

        return;
    }

    // Read section headers
    DWORD numberOfSections = ntHeaders.FileHeader.NumberOfSections;
    LPVOID sectionHeaderAddress = (LPBYTE)ntHeaderAddress + sizeof(IMAGE_NT_HEADERS);
    sectionHeaders.resize(numberOfSections);
    if (!ReadProcessMemory(hProcess, sectionHeaderAddress, sectionHeaders.data(),
        sizeof(IMAGE_SECTION_HEADER) * numberOfSections, NULL)) {
        LOG_A(LOG_WARNING, "ProcessQuery: Failed to read section headers. Error: %lu", GetLastError());
        return;
    }

    // PE header, but is this really true?
	uint64_t a = reinterpret_cast<uint64_t>(moduleBase);
    MemoryRegion* memoryRegionPe = new MemoryRegion(
        moduleNameStr + ": .PE_hdr", a, 4096, "r"
    );
    g_MemStatic.AddMemoryRegion(
        a,
        memoryRegionPe);

    // Print the sections
    for (const auto& section : sectionHeaders) {
        LPVOID sectionAddress = (LPBYTE)moduleBase + section.VirtualAddress;
        DWORD sectionSize = section.Misc.VirtualSize;

        // Super special constructor so no trailing zeros are in the string
        std::string sectionName(reinterpret_cast<const char*>(section.Name), strnlen(reinterpret_cast<const char*>(section.Name), 8));
        std::string full = moduleNameStr + ": " + sectionName;

        MemoryRegion* memoryRegion = new MemoryRegion(
            full,
            reinterpret_cast<uint64_t>(sectionAddress),
            sectionSize,
            GetSectionPermissions(section.Characteristics)
        );

        g_MemStatic.AddMemoryRegion(
            reinterpret_cast<uint64_t>(sectionAddress),
            memoryRegion);
    }
}


BOOL ProcessAddrInfo(HANDLE hProcess, DWORD address) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T returnLength = 0;
    if (! NtQueryVirtualMemory(hProcess, (PVOID)address, MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength) == 0) {
        LOG_A(LOG_WARNING, "ProcessQuery: Could not query memory address 0x%llx in process 0x%x", address, hProcess);
    }

    // return?
	return TRUE;
}


// Unused, produces a lot of data
bool QueryMemoryRegions(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    PVOID address = 0;
    SIZE_T returnLength = 0;
    char buf[DATA_BUFFER_SIZE];

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
        c += (int)strlen(buf);
        cc += 1;
        printf("%s\n", buf);

        //printf("Protection: ");
        //PrintProtectionFlags(mbi.Protect);
        address = (PVOID)((ULONG_PTR)mbi.BaseAddress + mbi.RegionSize);
    }

    printf("Len bytes: %i   lines: %i\n", c, cc);

    return TRUE;
}


// Utils

std::string GetSectionPermissions(DWORD characteristics) {
    std::string permissions;

    if (characteristics & IMAGE_SCN_MEM_READ)
        permissions += "r";
    if (characteristics & IMAGE_SCN_MEM_WRITE)
        permissions += "w";
    if (characteristics & IMAGE_SCN_MEM_EXECUTE)
        permissions += "x";

    if (permissions.empty())
        permissions = "none";

    return permissions;
}


// Gets a UNICODE_STRING content in a remote process as wstring
std::wstring GetRemoteUnicodeStr(HANDLE hProcess, UNICODE_STRING* u) {
    std::wstring s;
    //std::vector<wchar_t> commandLine(u->Length / sizeof(wchar_t));
    std::vector<wchar_t> uni(u->Length);
    if (!ReadProcessMemory(hProcess, u->Buffer, uni.data(), u->Length, NULL)) {
        LOG_A(LOG_ERROR, "ProcessQuery: Could not ReadProcessMemory error: %d", GetLastError());
    }
    else {
        s.assign(uni.begin(), uni.end());
    }
    return s;
}


wchar_t* GetFileNameFromPath(wchar_t* path) {
    wchar_t* lastBackslash = wcsrchr(path, L'\\');
    return (lastBackslash != NULL) ? lastBackslash + 1 : path;
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