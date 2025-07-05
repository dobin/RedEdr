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
#include <mutex>
#include <tlhelp32.h>
#include <set>

#include "logging.h"
#include "process_resolver.h"
#include "utils.h"
#include "process_query.h"
#include "config.h"
#include "event_aggregator.h"

/*
 * ProcessResolver: Maintains a cache of process information
 * 
 * Features:
 * - Thread-safe caching of Process objects indexed by PID
 * - Automatic population of all running processes on startup
 * - Cache refresh capability to track new/terminated processes
 * - Statistics and monitoring functions
 */


ProcessResolver g_ProcessResolver;
std::mutex cache_mutex;


ProcessResolver::ProcessResolver() {
}


// Add an object to the cache
void ProcessResolver::addObject(DWORD id, const Process& obj) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    cache[id] = obj;
}


BOOL ProcessResolver::containsObject(DWORD pid) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    auto it = cache.find(pid);
    if (it != cache.end()) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}


// Get an object from the cache
Process* ProcessResolver::getObject(DWORD id) {
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        auto it = cache.find(id);
        if (it != cache.end()) {
            return &it->second; // Return a pointer to the object
        }
    }

    // Does not exist, create and add to cache
    Process* process = MakeProcess(id, g_Config.targetExeName);
    if (process == nullptr) {
        return nullptr;
    }

    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        cache[id] = *process;
    }
    
    // Clean up the temporary process object
    delete process;
    
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        return &cache[id];
    }
}


BOOL ProcessResolver::observe(DWORD id) {
    Process* p = getObject(id);
    if (p != NULL) {
        return p->doObserve();
    }
    return FALSE;
}


// Remove an object from the cache
void ProcessResolver::removeObject(DWORD id) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    cache.erase(id);
}


void ProcessResolver::ResetData() {
    std::lock_guard<std::mutex> lock(cache_mutex);
    cache.clear();
}


size_t ProcessResolver::GetCacheCount() {
    std::lock_guard<std::mutex> lock(cache_mutex);
    return cache.size();
}


// Populate cache with all currently running processes
BOOL ProcessResolver::PopulateAllProcesses() {
    LOG_A(LOG_INFO, "ProcessResolver: Starting to populate cache with all running processes");
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "ProcessResolver: Failed to create process snapshot: %lu", GetLastError());
        return FALSE;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    // Get the first process
    if (!Process32First(hSnapshot, &pe32)) {
        LOG_A(LOG_ERROR, "ProcessResolver: Failed to get first process: %lu", GetLastError());
        CloseHandle(hSnapshot);
        return FALSE;
    }
    
    int processCount = 0;
    int cachedCount = 0;
    
    try {
        do {
            processCount++;
            DWORD pid = pe32.th32ProcessID;
            
            // Skip system idle process (PID 0)
            if (pid == 0) {
                continue;
            }
            
            // Check if already in cache
            if (containsObject(pid)) {
                continue;
            }
            
            // Create process object and add to cache
            Process* process = MakeProcess(pid, g_Config.targetExeName);
            if (process != nullptr) {
                {
                    std::lock_guard<std::mutex> lock(cache_mutex);
                    cache[pid] = *process;
                }
                
                // Clean up the temporary process object
                delete process;
                cachedCount++;
                
                // Log progress for large numbers of processes
                //if (cachedCount % 50 == 0) {
                //    LOG_A(LOG_DEBUG, "ProcessResolver: Cached %d processes so far...", cachedCount);
                //}
            }
            else {
                // MakeProcess can fail for protected/system processes, this is normal
                LOG_A(LOG_DEBUG, "ProcessResolver: Failed to create process object for PID %lu (%ls)", 
                      pid, pe32.szExeFile);
            }
            
        } while (Process32Next(hSnapshot, &pe32));
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "ProcessResolver: Exception while populating cache: %s", e.what());
        CloseHandle(hSnapshot);
        return FALSE;
    }
    catch (...) {
        LOG_A(LOG_ERROR, "ProcessResolver: Unknown exception while populating cache");
        CloseHandle(hSnapshot);
        return FALSE;
    }
    
    CloseHandle(hSnapshot);
    
    LOG_A(LOG_INFO, "ProcessResolver: Successfully populated cache with %d processes out of %d total processes", 
          cachedCount, processCount);
    //LOG_A(LOG_INFO, "ProcessResolver: Current cache size: %zu", GetCacheCount());
    
    return TRUE;
}


// Log statistics about the current cache state
void ProcessResolver::LogCacheStatistics() {
    std::lock_guard<std::mutex> lock(cache_mutex);
    LOG_A(LOG_INFO, "ProcessResolver: Total cached processes: %zu", cache.size());
}

