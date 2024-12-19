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


class Process {
public:
    Process();
    Process(DWORD _id);
    void display() const;
    wchar_t* serialize() const;
    BOOL doObserve();

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

    unsigned int augmented = 0;
};


Process* MakeProcess(DWORD pid, LPCWSTR target_name);
