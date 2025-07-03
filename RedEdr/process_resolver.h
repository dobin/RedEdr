#pragma once

#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <unordered_map>
#include <memory>
#include <tchar.h>

#include "process.h"
#include "process_query.h"


class ProcessResolver {
public:
    ProcessResolver();
    size_t GetCacheCount();
    void addObject(DWORD id, const Process& obj);
    BOOL containsObject(DWORD pid);
    Process* getObject(DWORD id);
    BOOL observe(DWORD id);
    void removeObject(DWORD id);
    void ResetData();
    BOOL PopulateAllProcesses(); // Populate cache with all running processes
    void LogCacheStatistics(); // Log statistics about the cache
    BOOL RefreshCache(); // Refresh cache with new processes and remove dead ones

private:
    std::unordered_map<DWORD, Process> cache;
};

// Declare a global instance
extern ProcessResolver g_ProcessResolver;
