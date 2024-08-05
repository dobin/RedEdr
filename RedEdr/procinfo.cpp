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

#include <psapi.h>
#include <tchar.h>
#include <stdio.h>
#include <vector>
#include <winternl.h>

#include "config.h"
#include "procinfo.h"
#include "cache.h"


#pragma comment(lib, "ntdll.lib")


typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength);


// Returns: Process PEB ProcessParameters CommandLine
BOOL GetProcessCommandLine_Peb(Process *process, HANDLE hProcess) {
    BOOL bSuccess = FALSE;
    std::wstring commandLinePeb = L"";
    
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        wprintf(L"Error: Could not get NtQueryInformationProcess for %d, error: %d\n", process->id, GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        wprintf(L"Error: Could not NtQueryInformationProcess for %d, error: %d\n", status, GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    PEB peb;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
        wprintf(L"Error: Could not ReadProcessMemory1 for %d, error: %d\n", process->id, GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    RTL_USER_PROCESS_PARAMETERS procParams;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), NULL)) {
        wprintf(L"Error: Could not ReadProcessMemory2 for %d, error: %d\n", process->id, GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    std::vector<wchar_t> commandLine(procParams.CommandLine.Length / sizeof(wchar_t));
    if (!ReadProcessMemory(hProcess, procParams.CommandLine.Buffer, commandLine.data(), procParams.CommandLine.Length, NULL)) {
        wprintf(L"Error: Could not ReadProcessMemory3 for %d, error: %d\n", process->id, GetLastError());
    }
    else {
        process->commandline.assign(commandLine.begin(), commandLine.end());
        bSuccess = TRUE;
    }

    return bSuccess;
}


// Returns: GetProcessImageFileName 
BOOL GetProcessImagePath_ProcessImage(Process *process, HANDLE hProcess) {
    wchar_t _str[MAX_PATH] = { 0 };
    LPWSTR str = _str;  // LPWSTR is *wchar_t

    if (GetProcessImageFileName(hProcess, str, MAX_PATH)) {
        process->image_path = std::wstring(str);
        return TRUE;
    }
    else {
        process->image_path = std::wstring(L"unknown");
        return FALSE;
    }
}


// Function to extract the working directory from the environment block
std::wstring GetWorkingDirectoryFromEnvironmentBlock(const std::vector<wchar_t>& environmentBlock) {
    const wchar_t* env = environmentBlock.data();
    while (*env) {
        std::wstring envVar(env);
        if (envVar.find(L"CD=") == 0) {
            return envVar.substr(3); // Extract the directory path after "CD="
        }
        env += wcslen(env) + 1; // Move to the next environment variable
    }
    return L"";
}

// Function to get the working directory of a process
BOOL GetProcessWorkingDirectory(Process* process, HANDLE hProcess) {
    return TRUE;
}


BOOL GetProcessParentPid(Process *process, HANDLE hProcess) {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

    if (NtQueryInformationProcess == nullptr) {
        std::cerr << "Failed to get NtQueryInformationProcess address" << std::endl;
        return FALSE;
    }

    NTSTATUS status = NtQueryInformationProcess(
        hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        std::cerr << "NtQueryInformationProcess failed: " << status << std::endl;
        return FALSE;
    }

    DWORD parentPid = (DWORD)pbi.Reserved3; // InheritedFromUniqueProcessId lol
    process->parent_pid = parentPid;

    return TRUE;
}


Process* MakeProcess(DWORD pid) {
    Process* process = new Process(pid);

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        printf("Could not open process:\n");
        printf("  %lu  %ls\n", pid, process->image_path.c_str());
        printf("  %lu:\n", GetLastError());
        return process;
    }

    // ppid
    if (!GetProcessParentPid(process, hProcess)) {
        printf("GetProcessParentPid error\n");
        CloseHandle(hProcess);
        return process;
    }

    // Process Image (ProcessImage)
    if (!GetProcessImagePath_ProcessImage(process, hProcess)) {
        printf("GetProcessImagePath_ProcessImage error\n");
        CloseHandle(hProcess);
        return process;
    }

    // Command Line (PEB)
    if (!GetProcessCommandLine_Peb(process, hProcess)) {
        printf("GetProcessCommandLine_Peb error\n");
        CloseHandle(hProcess);
        return process;
    }

    // Working dir (broken?)
    if (!GetProcessWorkingDirectory(process, hProcess)) {
        printf("GetProcessWorkingDirectory error\n");
        CloseHandle(hProcess);
        return process;
    }

    // CHECK: Observe
    BOOL observe = FALSE;
    //if (wcsstr(process_image, g_config.targetExeName)) {
    if (process->image_path.find(g_config.targetExeName) != std::wstring::npos) {
        // CHECK: Process name
        wprintf(L"Observe CMD: %d %ls\n", pid, process->image_path.c_str());
        observe = TRUE;
    }
    if (g_cache.containsObject(process->parent_pid)) { // dont recursively resolve all
        // CHECK: Parent observed?
        if (g_cache.getObject(process->parent_pid)->doObserve()) {
            printf("Observe PID: %d (because PPID %d): %ls\n", pid, process->parent_pid, process->image_path.c_str());
            observe = TRUE;
        }
    }

    CloseHandle(hProcess);
    return process;
}
