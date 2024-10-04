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

#include "procinfo.h"
#include "cache.h"


class Cache {
public:
    Cache();
    void addObject(DWORD id, const Process& obj);
    BOOL containsObject(DWORD pid);
    Process* getObject(DWORD id);
    BOOL observe(DWORD id);
    void removeObject(DWORD id);

private:
    std::unordered_map<DWORD, Process> cache;
};

// Declare a global instance
extern Cache g_cache; 
