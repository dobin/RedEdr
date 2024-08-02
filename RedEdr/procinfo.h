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
    Process(DWORD id, BOOL observe, std::wstring path) : id(id), observe(observe), path(path) {}

    void display() const {
        //std::cout << "ID: " << id << ", Name: " << name << std::endl;
        wprintf(L"PID: %i  observe:%i  PATH: %ls\n",
            id, observe, path.c_str());
    }

    BOOL doObserve() {
        return observe;
    }

private:
    DWORD id;
    BOOL observe;
    std::wstring path;

};

Process* MakeProcess(DWORD pid);
BOOL GetProcessCommandLine(DWORD dwPID, std::wstring& cmdLine);
BOOL GetProcessCommandLine2(DWORD dwPID, LPTSTR lpCmdLine, DWORD dwSize);
BOOL GetProcessWorkingDirectory2(DWORD dwPID, LPTSTR lpDirectory, DWORD dwSize);

