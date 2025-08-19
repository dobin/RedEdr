#include <Windows.h>
#include <stdio.h>
#include "uthash.h"
#include <psapi.h>
#include <vector>
#include <string>
#include <tlhelp32.h>

#include "objcache.h"
#include "logging.h"

struct my_hashmap* map = NULL;
HANDLE mutex;
std::vector<std::string> target_names;


// Helper function to get process name by PID using CreateToolhelp32Snapshot
std::wstring GetProcessNameByPid(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LOG_W(LOG_ERROR, L"GetProcessNameByPid: Failed to create process snapshot: %lu", GetLastError());
        return std::wstring(L"");
    }
    
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    
    // Get the first process
    if (!Process32FirstW(hSnapshot, &pe32)) {
        LOG_W(LOG_ERROR, L"GetProcessNameByPid: Failed to get first process: %lu", GetLastError());
        CloseHandle(hSnapshot);
        return std::wstring(L"");
    }
    
    std::wstring processName;
    do {
        if (pe32.th32ProcessID == pid) {
            processName = std::wstring(pe32.szExeFile);
            break;
        }
    } while (Process32NextW(hSnapshot, &pe32));
    
    CloseHandle(hSnapshot);
    
    return processName;
}


void RefreshProcessMatching() {
    struct my_hashmap* entry = NULL;
    struct my_hashmap* tmp = NULL;

    WaitForSingleObject(mutex, INFINITE);
    HASH_ITER(hh, map, entry, tmp) {
        int pid = entry->key;
        std::wstring exePath = GetProcessNameByPid(pid);
        if (match_process(exePath)) {
            entry->value = 1;
            LOG_W(LOG_INFO, L"Objcache: Observe PID %d processname %s", entry->key, exePath.c_str());
        } else {
            entry->value = 0;
        }
    }
    ReleaseMutex(mutex);
}


void set_target_names(const std::vector<std::string>& targets) {
    target_names.clear();
    target_names = targets;
    LOG_W(LOG_INFO, L"Objcache: Set %zu target names", targets.size());

    RefreshProcessMatching();
}


bool match_process(std::wstring exePath) {
    if (exePath.empty() || target_names.empty()) {
        return false;
    }

    // Check against all target names
    for (const auto& target : target_names) {
        wchar_t target_wide[MAX_PATH];
        mbstowcs_s(NULL, target_wide, MAX_PATH, target.c_str(), _TRUNCATE);
        const wchar_t* result = wcsstr(exePath.c_str(), target_wide);
        if (result) {
            return true;
        }
    }
    return false;
}


void objcache_init() {
    mutex = CreateMutex(NULL, FALSE, NULL);
    
    // Populate map with all existing processes
    // Match them already with our observed processes
    DWORD processes[1024], cbNeeded, processCount;
    if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        processCount = cbNeeded / sizeof(DWORD);
        
        for (DWORD i = 0; i < processCount; i++) {
            if (processes[i] != 0) {
                int pid = processes[i];
                int observe = 0;
                std::wstring exePath = GetProcessNameByPid(pid);
                if (match_process(exePath)) {
                    LOG_W(LOG_INFO, L"Objcache Init: observe process %lu executable path: %s", pid, exePath.c_str());
                    observe = 1;
                }
                add_obj(pid, observe);
            }
        }
        LOG_W(LOG_INFO, L"Objcache Init: Initialized with %lu existing processes", processCount);
    }
    else {
        LOG_W(LOG_INFO, L"Objcache Init: Failed to enumerate processes during init: %lu", GetLastError());
    }
}


struct my_hashmap* get_obj(int pid) {
    struct my_hashmap* obj = NULL;
    obj = has_obj(pid);
    if (obj != NULL) {
        return obj;
    }
    
    // Resolve and add if not found
    int observe = 0;
    if (!target_names.empty()) {
        std::wstring exePath = GetProcessNameByPid(pid);
        if (match_process(exePath)) {
            LOG_W(LOG_INFO, L"Objcache: observe process %lu executable path: %s", pid, exePath.c_str());
            observe = 1;
        } else {
            LOG_W(LOG_INFO, L"Objcache: Failed to get executable path for PID: %lu\n", pid);
        }
    }
    struct my_hashmap* res = add_obj(pid, observe);
    return res;
}


struct my_hashmap* add_obj(int pid, int observe) {
    struct my_hashmap* entry = NULL;
    entry = (struct my_hashmap*) malloc(sizeof(struct my_hashmap));
    entry->key = pid;
    entry->value = observe;
    WaitForSingleObject(mutex, INFINITE);
    HASH_ADD_INT(map, key, entry);
    ReleaseMutex(mutex);
    return entry;
}


struct my_hashmap* has_obj(int key) {
    struct my_hashmap* entry = NULL;
    WaitForSingleObject(mutex, INFINITE);
    HASH_FIND_INT(map, &key, entry);
    ReleaseMutex(mutex);
    return entry;
}


void clean_obj() {
    WaitForSingleObject(mutex, INFINITE);
    struct my_hashmap* entry = NULL, * tmp = NULL;
    HASH_ITER(hh, map, entry, tmp) {
        HASH_DEL(map, entry);
        free(entry);
    }
    target_names.clear();
    ReleaseMutex(mutex);
}

