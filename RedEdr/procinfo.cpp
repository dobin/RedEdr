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
BOOL GetProcessCommandLine_Peb(DWORD dwPID, std::wstring& cmdLine) {
    BOOL bSuccess = FALSE;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
    if (!hProcess) {
        //printf("Could not open process:\n");
        //printf("  %lu  %commandLinePeb\n", dwPID, process_image.c_str());
        //printf("  %lu:\n", GetLastError());
        return FALSE;
    }

    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (!NtQueryInformationProcess) {
        wprintf(L"Error: Could not get NtQueryInformationProcess for %d, error: %d\n", dwPID, GetLastError());
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
        wprintf(L"Error: Could not ReadProcessMemory1 for %d, error: %d\n", dwPID, GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    RTL_USER_PROCESS_PARAMETERS procParams;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &procParams, sizeof(procParams), NULL)) {
        wprintf(L"Error: Could not ReadProcessMemory2 for %d, error: %d\n", dwPID, GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    std::vector<wchar_t> commandLine(procParams.CommandLine.Length / sizeof(wchar_t));
    if (!ReadProcessMemory(hProcess, procParams.CommandLine.Buffer, commandLine.data(), procParams.CommandLine.Length, NULL)) {
        wprintf(L"Error: Could not ReadProcessMemory3 for %d, error: %d\n", dwPID, GetLastError());
    }
    else {
        cmdLine.assign(commandLine.begin(), commandLine.end());
        bSuccess = TRUE;
    }

    CloseHandle(hProcess);
    return bSuccess;
}


// Returns: GetProcessImageFileName 
BOOL GetProcessImagePath_ProcessImage(DWORD dwPID, LPWSTR lpCmdLine, DWORD dwSize) {
    BOOL bSuccess = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
    if (hProcess != NULL) {
        if (GetProcessImageFileName(hProcess, lpCmdLine, dwSize)) {
            bSuccess = TRUE;
        }
        CloseHandle(hProcess);
    }
    return bSuccess;
}

// Function to get the working directory of a process
BOOL GetProcessWorkingDirectory(DWORD dwPID, LPWSTR lpDirectory, DWORD dwSize) {
    BOOL bSuccess = FALSE;
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwPID);
    if (hProcess != NULL) {
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            if (GetModuleFileNameEx(hProcess, hMod, lpDirectory, dwSize)) {
                // Remove the executable name to get the directory
                TCHAR* p = _tcsrchr(lpDirectory, '\\');
                if (p) {
                    *p = '\0';
                    bSuccess = TRUE;
                }
            }
        }
        CloseHandle(hProcess);
    }
    return bSuccess;
}


DWORD GetProcessParentPid(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        //std::cerr << "Could not open process: " << GetLastError() << std::endl;
        return 0;
    }

    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    pNtQueryInformationProcess NtQueryInformationProcess =
        (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");

    if (NtQueryInformationProcess == nullptr) {
        std::cerr << "Failed to get NtQueryInformationProcess address" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    NTSTATUS status = NtQueryInformationProcess(
        hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength);
    if (status != 0) {
        std::cerr << "NtQueryInformationProcess failed: " << status << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    DWORD parentPid = (DWORD)pbi.Reserved3; // InheritedFromUniqueProcessId lol
    CloseHandle(hProcess);
    return parentPid;
}


Process* MakeProcess(DWORD pid) {
    wchar_t _cmdLine[MAX_PATH] = { 0 };  
    wchar_t _workingDir[MAX_PATH] = { 0 };
    LPWSTR process_image = _cmdLine;  // LPWSTR is *wchar_t
    LPWSTR workingDir = _workingDir;

    // Process Image (ProcessImage)
    if (!GetProcessImagePath_ProcessImage(pid, process_image, MAX_PATH)) {
        wcscpy_s(process_image, MAX_PATH, L"unknown");
    }

    // Command Line (PEB)
    std::wstring commandLinePeb;
    GetProcessCommandLine_Peb(pid, commandLinePeb);

    // Working dir (broken?)
    if (!GetProcessWorkingDirectory(pid, workingDir, MAX_PATH)) {
        wcscpy_s(workingDir, MAX_PATH, L"unknown");
    }

    DWORD parent_pid = GetProcessParentPid(pid);

    // CHECK: Observe
    BOOL observe = FALSE;
    if (wcsstr(process_image, g_config.targetExeName)) {
        // CHECK: Process name
        printf("Observe CMD: %d %ls\n", pid, process_image);
        observe = TRUE;
    }
    DWORD ppid = GetProcessParentPid(pid);
    if (g_cache.containsObject(ppid)) { // dont recursively resolve all
        // CHECK: Parent observed?
        if (g_cache.getObject(ppid)->doObserve()) {
            printf("Observe PID: %d (because PPID %d): %ls\n", pid, ppid, process_image);
            observe = TRUE;
        }
    }

    // Make process with all this data
    Process* obj = new Process(pid, parent_pid, observe, process_image, commandLinePeb, workingDir);
    return obj;
}
