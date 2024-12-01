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

#include "processinfo.h"
#include "processcache.h"


class ProcessCache {
public:
    ProcessCache();
    size_t GetCacheCount();
    void addObject(DWORD id, const Process& obj);
    BOOL containsObject(DWORD pid);
    Process* getObject(DWORD id);
    BOOL observe(DWORD id);
    void removeObject(DWORD id);
    void removeAll();

private:
    std::unordered_map<DWORD, Process> cache;
};

// Declare a global instance
extern ProcessCache g_ProcessCache; 
