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
    BOOL doObserve();
    BOOL OpenTarget();
    BOOL CloseTarget();
    HANDLE GetHandle();

public:
    // Internal
    DWORD id = 0;
    BOOL observe = 0;
    unsigned int augmented = 0;

    std::wstring commandline;
    HANDLE hProcess;
};


Process* MakeProcess(DWORD pid, LPCWSTR target_name);
