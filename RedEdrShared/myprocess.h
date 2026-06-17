#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <atomic>

#include "process_query.h"
#include "process_mem_static.h"


class Process {
public:
    Process();
    Process(DWORD _id);
    ~Process();  // Destructor to clean up all data

    // Owning type: no copies (MemStatic owns heap memory)
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;
    Process(Process&&) = default;
    Process& operator=(Process&&) = default;

    BOOL doObserve();

    bool ObserveIfMatchesTargets(const std::vector<std::string>& targetNames);
    bool AugmentInfo();

    BOOL OpenTarget();
    BOOL CloseTarget();
    HANDLE GetHandle();

public:
    DWORD id = 0;
    BOOL observe = FALSE;

    std::atomic<BOOL> augmented{FALSE};

    std::string name;
    std::string commandline;

    // When augmented
    std::vector<ProcessLoadedDll> processLoadedDlls;
    ProcessPebInfoRet processPebInfoRet;
    MemStatic memStatic;

private:
    HANDLE hProcess = NULL;
};


Process* MakeProcess(DWORD pid, std::vector<std::string> targetNames);
