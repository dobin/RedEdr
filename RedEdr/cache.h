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


class Cache {
public:
    Cache() {

    }

    // Add an object to the cache
    void addObject(DWORD id, const Process& obj) {
        cache[id] = obj;
    }

    // Get an object from the cache
    Process* getObject(DWORD id) {
        auto it = cache.find(id);
        if (it != cache.end()) {
            return &it->second; // Return a pointer to the object
        }

        // Does not exist, create and add to cache

        TCHAR cmdLine[MAX_PATH] = { 0 };
        TCHAR workingDir[MAX_PATH] = { 0 };
        GetProcessCommandLine2(id, cmdLine, MAX_PATH);
        //printf("GetProcessCommandLine2: %ls\n", cmdLine);

        GetProcessWorkingDirectory2(id, workingDir, MAX_PATH);
        //printf("GetProcessWorkingDirectory2: %ls\n", workingDir);

        std::wstring path;
        GetProcessCommandLine(id, path);
        //printf("GetProcessCommandLine: %ls\n", path);

        BOOL observe = FALSE;
        if (_tcsstr(cmdLine, _T("notepad.exe"))) {
            observe = TRUE;
        }

        Process obj(id, observe, cmdLine);
        cache[id] = obj;
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