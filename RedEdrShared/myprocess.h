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
    DWORD id = 0;
    BOOL observe = FALSE;
    unsigned int augmented = 0;
    BOOL initialized = FALSE;

    std::string name;
    std::string commandline;
    HANDLE hProcess;
};

bool ProcessMatchesAnyTarget(const std::string& processName, const std::vector<std::string>& targetNames);
Process* MakeProcess(DWORD pid, std::vector<std::string> targetNames);
