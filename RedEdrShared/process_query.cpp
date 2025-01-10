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

#include "process_query.h"
#include "logging.h"
#include "utils.h"
#include "mypeb.h"

#include "../Shared/common.h"

#pragma comment(lib, "ntdll.lib")

/* Process Query
 * Provides functions to query a process for more information
 * No side effects
 */


 // Private
wchar_t* GetFileNameFromPath(wchar_t* path);
std::string GetRemoteUnicodeStr(HANDLE hProcess, UNICODE_STRING* u);


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


std::wstring GetProcessName(HANDLE hProcess) {
    WCHAR exePath[MAX_PATH];
    if (GetModuleFileNameEx(hProcess, NULL, exePath, MAX_PATH)) {
        return std::wstring(exePath);
    }
    else {
        return std::wstring(L"");
    }
}


// Process: PEB Info
ProcessPebInfoRet ProcessPebInfo(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    ProcessPebInfoRet processPebInfoRet;

    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        LOG_A(LOG_ERROR, "ProcessPebInfo: Could not NtQueryInformationProcess, ret: %lu, error: %d",
            status, GetLastError());
        return processPebInfoRet;
    }

    // PPID
    DWORD parentPid = reinterpret_cast<DWORD>(pbi.Reserved3); // InheritedFromUniqueProcessId lol
    processPebInfoRet.parent_pid = parentPid;

    // PEB
    MYPEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        LOG_A(LOG_WARNING, "ProcessPebInfo: Error: Could not ReadProcessMemory1 error: %d",
            GetLastError());
        return processPebInfoRet;
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
    processPebInfoRet.is_debugged = peb.BeingDebugged;
    processPebInfoRet.is_protected_process = peb.IsProtectedProcess;
    processPebInfoRet.is_protected_process_light = peb.IsProtectedProcessLight;
    processPebInfoRet.image_base = pointer_to_uint64(peb.ImageBaseAddress);

    // ProcessParameters - anoying copying
    MY_RTL_USER_PROCESS_PARAMETERS procParams;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), NULL)) {
        LOG_A(LOG_ERROR, "ProcessQuery: Error: Could not ReadProcessMemory error: %d", GetLastError());
        return processPebInfoRet;
    }
    processPebInfoRet.commandline = GetRemoteUnicodeStr(hProcess, &procParams.CommandLine);
    processPebInfoRet.image_path = GetRemoteUnicodeStr(hProcess, &procParams.ImagePathName);
    processPebInfoRet.working_dir = GetRemoteUnicodeStr(hProcess, &procParams.CurrentDirectory.DosPath);

    // No need for these for now
    //std::wstring DllPath = my_get_str(hProcess, &procParams.DllPath);
    //std::wstring WindowTitle = my_get_str(hProcess, &procParams.WindowTitle);

    return processPebInfoRet;
}


std::wstring ReadMemoryAsWString(HANDLE hProcess, LPCVOID remoteAddress, SIZE_T byteCount) {
    if (!hProcess || !remoteAddress || byteCount == 0) {
        throw std::invalid_argument("Invalid arguments provided to ReadMemoryAsWString");
    }

    // Allocate buffer to hold the memory content
    std::vector<WCHAR> buffer(byteCount / sizeof(WCHAR) + 1, L'\0'); // Extra space for null-terminator
    SIZE_T bytesRead = 0;

    // Read the memory from the target process
    if (!ReadProcessMemory(hProcess, remoteAddress, buffer.data(), byteCount, &bytesRead)) {
        throw std::runtime_error("ReadProcessMemory failed");
    }

    // Ensure the memory read is within bounds
    SIZE_T wcharCount = bytesRead / sizeof(WCHAR);
    if (wcharCount < buffer.size()) {
        buffer[wcharCount] = L'\0'; // Null-terminate if not already
    }
    else {
        buffer.back() = L'\0'; // Guarantee null-termination in case of truncation
    }

    // Return as a wstring
    return std::wstring(buffer.data());
}


// Enumerate all modules loaded in the process (DLL's), and their sections
std::vector<ProcessLoadedDll> ProcessEnumerateModules(HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    std::vector <ProcessLoadedDll> processLoadedDlls;

    // PBI
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        LOG_A(LOG_ERROR, "ProcessEnumerateModules: Error: Could not NtQueryInformationProcess for %d, error: %d", status, GetLastError());
        return processLoadedDlls;
    }

    // PEB
    MYPEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        LOG_A(LOG_WARNING, "ProcessEnumerateModules: Error: Could not ReadProcessMemory1 error: %d",
            GetLastError());
        return processLoadedDlls;
    }

    // PEB_LDR_DATA
    PEB_LDR_DATA ldr;
    if (!ReadProcessMemory(hProcess, peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), NULL)) {
        printf("ProcessEnumerateModules: ReadProcessMemory failed for PEB_LDR_DATA\n");
        return processLoadedDlls;
    }

    // InMemoryOrderModuleList
    LIST_ENTRY* head = &ldr.InMemoryOrderModuleList;
    LIST_ENTRY* current = ldr.InMemoryOrderModuleList.Flink;
    while (current != head) {
        ProcessLoadedDll processLoadedDll;

        _LDR_DATA_TABLE_ENTRY entry;
        if (!ReadProcessMemory(hProcess, CONTAINING_RECORD(current, _LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks),
            &entry, sizeof(_LDR_DATA_TABLE_ENTRY), NULL))
        {
            printf("ProcessEnumerateModules: ReadProcessMemory failed for LDR_DATA_TABLE_ENTRY\n");
            return processLoadedDlls;
        }
        if (entry.DllBase == 0) { // all zero is last one for some reason
            break;
        }
        std::wstring filenameW = ReadMemoryAsWString(hProcess, entry.FullDllName.Buffer, entry.FullDllName.Length);
		std::string filenameStr = wstring2string(filenameW);
        processLoadedDll.dll_base = pointer_to_uint64(entry.DllBase);
        processLoadedDll.size = (ULONG)entry.Reserved3[1];
        processLoadedDll.name = filenameStr;
        processLoadedDlls.push_back(processLoadedDll);

        // Move to the next module in the list
        current = entry.InMemoryOrderLinks.Flink;
    }

    return processLoadedDlls;
}


std::string GetSectionNameFromRaw(const IMAGE_SECTION_HEADER& section) {
    return std::string(reinterpret_cast<const char*>(section.Name),
        strnlen(reinterpret_cast<const char*>(section.Name), 8));
}


std::vector<ModuleSection> EnumerateModuleSections(HANDLE hProcess, LPVOID moduleBase) {
    std::vector<ModuleSection> moduleSections;

    // Buffer for headers
    IMAGE_DOS_HEADER dosHeader = {};
    IMAGE_NT_HEADERS ntHeaders = {};
    std::vector<IMAGE_SECTION_HEADER> sectionHeaders;

    // Buffer for module name
    wchar_t moduleName[MAX_PATH] = { 0 };
    if (!GetModuleBaseName(hProcess, (HMODULE)moduleBase, moduleName, MAX_PATH)) {
        LOG_A(LOG_WARNING, "ProcessQuery: Failed to retrieve module name. Error: %lu", GetLastError());
        return moduleSections;
    }
    std::string moduleNameStr = wchar2string(moduleName);

    // Read the DOS header
    if (!ReadProcessMemory(hProcess, moduleBase, &dosHeader, sizeof(dosHeader), NULL)) {
        LOG_A(LOG_WARNING, "ProcessQuery: Failed to read DOS header. Error: %lu", GetLastError());
        return moduleSections;
    }
    // Verify DOS signature
    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        LOG_A(LOG_WARNING, "ProcessQuery: Invalid DOS signature. Not a valid PE file");
        return moduleSections;
    }
    // Read the NT header
    LPVOID ntHeaderAddress = (LPBYTE)moduleBase + dosHeader.e_lfanew;
    if (!ReadProcessMemory(hProcess, ntHeaderAddress, &ntHeaders, sizeof(ntHeaders), NULL)) {
        LOG_A(LOG_WARNING, "ProcessQuery: Failed to read NT headers. Error: %lu", GetLastError());
        return moduleSections;
    }
    // Verify NT signature
    if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) {
        LOG_A(LOG_WARNING, "ProcessQuery: Invalid NT signature. Not a valid PE file.");
        return moduleSections;
    }

    // Read section headers
    DWORD numberOfSections = ntHeaders.FileHeader.NumberOfSections;
    LPVOID sectionHeaderAddress = (LPBYTE)ntHeaderAddress + sizeof(IMAGE_NT_HEADERS);
    sectionHeaders.resize(numberOfSections);
    if (!ReadProcessMemory(hProcess, sectionHeaderAddress, sectionHeaders.data(),
        sizeof(IMAGE_SECTION_HEADER) * numberOfSections, NULL)) {
        LOG_A(LOG_WARNING, "ProcessQuery: Failed to read section headers. Error: %lu", GetLastError());
        return moduleSections;
    }

    // Note: PE header, but is this really true?
    uint64_t a = reinterpret_cast<uint64_t>(moduleBase);
    ModuleSection memoryRegionPe = ModuleSection(
        moduleNameStr + ": .pehdr", a, 4096, "R--"
    );
    moduleSections.push_back(memoryRegionPe);

    for (const auto& section: sectionHeaders) {
        LPVOID sectionAddress = (LPBYTE)moduleBase + section.VirtualAddress;
        DWORD sectionSize = section.Misc.VirtualSize;

		std::string sectionName = GetSectionNameFromRaw(section);
        std::string full = moduleNameStr + ":" + sectionName;

        ModuleSection memoryRegion = ModuleSection(
            full,
            reinterpret_cast<uint64_t>(sectionAddress),
            sectionSize,
            GetSectionPermissions(section.Characteristics)
        );
        moduleSections.push_back(memoryRegion);
    }

    return moduleSections;
}


ProcessAddrInfoRet ProcessAddrInfo(HANDLE hProcess, PVOID address) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T returnLength = 0;
    if (!NtQueryVirtualMemory(hProcess, address, MemoryBasicInformation, &mbi, sizeof(mbi), &returnLength) == 0) {
        LOG_A(LOG_WARNING, "ProcessQuery: Could not query memory address 0x%llx in process 0x%x", address, hProcess);
    }

    ProcessAddrInfoRet processAddrInfoRet;
    processAddrInfoRet.name = "";
    processAddrInfoRet.base_addr = mbi.BaseAddress;
    processAddrInfoRet.allocation_base = mbi.AllocationBase;
    processAddrInfoRet.region_size = mbi.RegionSize;
    processAddrInfoRet.state = mbi.State;
    processAddrInfoRet.protect = mbi.Protect;
    processAddrInfoRet.type = mbi.Type;

    processAddrInfoRet.stateStr = getMemoryRegionState(mbi.State);
    processAddrInfoRet.protectStr = getMemoryRegionProtect(mbi.Protect);
    processAddrInfoRet.typeStr = getMemoryRegionType(mbi.Type);

    return processAddrInfoRet;
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


// Gets a UNICODE_STRING content in a remote process as wstring
std::string GetRemoteUnicodeStr(HANDLE hProcess, UNICODE_STRING* u) {
    std::wstring s;
    //std::vector<wchar_t> commandLine(u->Length / sizeof(wchar_t));
    std::vector<wchar_t> uni(u->Length);
    if (!ReadProcessMemory(hProcess, u->Buffer, uni.data(), u->Length, NULL)) {
        LOG_A(LOG_ERROR, "ProcessQuery: Could not ReadProcessMemory error: %d", GetLastError());
    }
    else {
        s.assign(uni.begin(), uni.end());
    }

	std::string str = wstring2string(s);
    return str;
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