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
    Cache() {

    }

    // Add an object to the cache
    void addObject(DWORD id, const Process& obj) {
        cache[id] = obj;
    }

    BOOL containsObject(DWORD pid) {
        auto it = cache.find(pid);
        if (it != cache.end()) {
            return TRUE;
        }
        else {
            return FALSE;
        }
    }

    // Get an object from the cache
    Process* getObject(DWORD id) {
        auto it = cache.find(id);
        if (it != cache.end()) {
            return &it->second; // Return a pointer to the object
        }

        // Does not exist, create and add to cache
        Process *process = MakeProcess(id);
        cache[id] = *process;
        return &cache[id];
    }

    BOOL observe(DWORD id) {
        Process *p = getObject(id);
        if (p != NULL) {
            return p->doObserve();
        }
        return FALSE;
    }

    // Remove an object from the cache
    void removeObject(DWORD id) {
        cache.erase(id);
    }

private:
    std::unordered_map<DWORD, Process> cache;
};


// Omg
extern Cache g_cache; // Declare a global instance
void test();