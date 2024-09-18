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
        observe = FALSE;
    }
    Process(DWORD id): id(id) {
        observe = FALSE;
    }

    void display() const {
        wprintf(L"PID: %i  parent: %i  observe: %i\n", id, parent_pid, observe);
        wprintf(L"         ImagePath: %ls\n", image_path.c_str());
        wprintf(L"         commandline: %ls\n", commandline.c_str());
        wprintf(L"         working_dir: %ls\n", working_dir.c_str());

        wprintf(L"         is_debugged: %d\n", is_debugged);
        wprintf(L"         is_protected_process: %d\n", is_protected_process);
        wprintf(L"         is_protected_process_light: %d\n", is_protected_process_light);
        wprintf(L"         image_base: 0x%p\n", image_base);
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
    DWORD id = 0;
    BOOL observe = 0;
    std::wstring image_path = L"";
    std::wstring commandline = L"";
    std::wstring working_dir = L"";
    DWORD parent_pid = 0;

    DWORD is_debugged = 0;
    DWORD is_protected_process = 0;
    DWORD is_protected_process_light = 0;
    PVOID image_base = 0;
    LPCVOID PebBaseAddress = 0;
};


Process* MakeProcess(DWORD pid);

