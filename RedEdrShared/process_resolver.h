#pragma once

#include <windows.h>
#include <unordered_map>

#include "myprocess.h"


class ProcessResolver {
public:
    ProcessResolver();
    
    void addObject(DWORD id, const Process& obj);
    BOOL containsObject(DWORD pid);
    Process* getObject(DWORD id);
    void removeObject(DWORD id);

    void ResetData();
    BOOL PopulateAllProcesses();
    void LogCacheStatistics();
    //void RefreshCache();
    void RefreshTargetMatching();

    void SetTargetNames(const std::vector<std::string>& names);
    size_t GetCacheCount();

private:
	std::vector<std::string> targetProcessNames = {};
    std::unordered_map<DWORD, Process> cache;
};

// Declare a global instance
extern ProcessResolver g_ProcessResolver;
