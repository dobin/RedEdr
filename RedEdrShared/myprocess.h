#pragma once

#include <windows.h>
#include <string>
#include <vector>

#include "process_query.h"
#include "process_mem_static.h"


class Process {
public:
    Process();
    Process(DWORD _id);
    ~Process();  // Destructor to clean up all data
    BOOL doObserve();

    bool ObserveIfMatchesTargets(const std::vector<std::string>& targetNames);
    bool AugmentInfo();

    BOOL OpenTarget();
    BOOL CloseTarget();
    HANDLE GetHandle();

public:
    DWORD id = 0;
    BOOL observe = FALSE;

    BOOL augmented = FALSE;

    std::string name;
    std::string commandline;

    // When augmented
    std::vector<ProcessLoadedDll> processLoadedDlls;
    ProcessPebInfoRet processPebInfoRet;
    MemStatic memStatic;


    HANDLE hProcess;
};


Process* MakeProcess(DWORD pid, std::vector<std::string> targetNames);
