#pragma once

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


class Process {
public:
    Process() {
    }
    Process(DWORD id): id(id) {}

    void display() const {
        wprintf(L"PID: %i  parent: %i  observe: %i\n", id, parent_pid, observe);
        wprintf(L"         ImagePath: %ls\n", image_path.c_str());
        wprintf(L"         commandline: %ls\n", commandline.c_str());
        wprintf(L"         working_dir: %ls\n", working_dir.c_str());
    }

    wchar_t* serialize() const {
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

    BOOL doObserve() {
        return observe;
    }

public:
    DWORD id;
    BOOL observe;
    std::wstring image_path;
    std::wstring commandline;
    std::wstring working_dir;
    DWORD parent_pid;

};


BOOL GetProcessCommandLine_Peb(Process* process, HANDLE hProcess);
BOOL GetProcessImagePath_ProcessImage(Process* process, HANDLE hProcess);
BOOL GetProcessWorkingDirectory(Process* process, HANDLE hProcess);
Process* MakeProcess(DWORD pid);
BOOL GetProcessParentPid(Process* process, HANDLE hProcess);
