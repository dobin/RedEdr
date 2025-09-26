#include <windows.h>
#include <iostream>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include <tlhelp32.h>

#include "process_resolver.h"
#include "../Shared/common.h"

// The implementation is in each solution
void LOG_W(int verbosity, const wchar_t* format, ...);
void LOG_A(int verbosity, const char* format, ...);


/*
 * ProcessResolver: Maintains a cache of processes to see if we should observe them
 * 
 * Features:
 * - Thread-safe caching of all processes / Process-objects indexed by PID
 * - Automatic population of all running processes on startup (speed)
 * - Cache refresh capability to track new/terminated processes
 * - Statistics and monitoring functions
 */


ProcessResolver g_ProcessResolver;
std::mutex cache_mutex;


ProcessResolver::ProcessResolver() {
	cache.reserve(2000); // Preallocate space for 2000 processes
}


ProcessResolver::~ProcessResolver() {
    StopCleanupThread();
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


void ProcessResolver::SetTargetNames(const std::vector<std::string>& names) {
    std::lock_guard<std::mutex> lock(cache_mutex);
    targetProcessNames = names;
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
    Process* process = MakeProcess(id, targetProcessNames);
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
            Process* process = MakeProcess(pid, targetProcessNames);
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
    
    LOG_A(LOG_INFO, "ProcessResolver: Successfully populated cache with %d processes", 
          cachedCount);
    //LOG_A(LOG_INFO, "ProcessResolver: Current cache size: %zu", GetCacheCount());
    
    return TRUE;
}


// Re-evaluate all cached processes with current target names
void ProcessResolver::RefreshTargetMatching() {
    LOG_A(LOG_INFO, "ProcessResolver: Re-evaluating all cached processes with current target names");
    std::lock_guard<std::mutex> lock(cache_mutex);
    
    for (auto& pair : cache) {
        DWORD pid = pair.first;
        Process& process = pair.second;
        process.ObserveIfMatchesTargets(targetProcessNames);
    }
}


// Log statistics about the current cache state
void ProcessResolver::LogCacheStatistics() {
    std::lock_guard<std::mutex> lock(cache_mutex);
    LOG_A(LOG_INFO, "ProcessResolver: Total cached processes: %zu", cache.size());
}


// Cleanup thread management
void ProcessResolver::StartCleanupThread(std::chrono::minutes interval) {
    if (cleanupThreadRunning.load()) {
        return; // Already running
    }
    
    cleanupInterval = interval;
    cleanupThreadRunning = true;
    cleanupThread = std::thread(&ProcessResolver::CleanupWorker, this);
    LOG_A(LOG_INFO, "ProcessResolver: Started cleanup thread with %d minute interval", 
          static_cast<int>(interval.count()));
}


void ProcessResolver::StopCleanupThread() {
    cleanupThreadRunning = false;
    if (cleanupThread.joinable()) {
        cleanupThread.join();
    }
    LOG_A(LOG_INFO, "ProcessResolver: Cleanup thread stopped");
}


void ProcessResolver::CleanupWorker() {
    while (cleanupThreadRunning.load()) {
        // Sleep for the specified interval, but check every second if we should stop
        for (int i = 0; i < cleanupInterval.count() * 60 && cleanupThreadRunning.load(); i++) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        if (cleanupThreadRunning.load()) {
            CleanupStaleProcesses();
        }
    }
}


void ProcessResolver::CleanupStaleProcesses() {
    LOG_A(LOG_INFO, "ProcessResolver: Starting cleanup of stale processes");
    
    std::vector<DWORD> pidsToRemove;
    size_t totalProcesses = 0;
    
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        totalProcesses = cache.size();
        
        for (const auto& pair : cache) {
            DWORD pid = pair.first;
            
            // Check if process is still alive
            if (!IsProcessAlive(pid)) {
                pidsToRemove.push_back(pid);
            }
        }
    }
    
    // Remove stale processes (outside the lock to avoid holding it too long)
    for (DWORD pid : pidsToRemove) {
        removeObject(pid);
    }
    
    if (!pidsToRemove.empty()) {
        LOG_A(LOG_INFO, "ProcessResolver: Cleaned up %zu stale processes (was: %zu, now: %zu)", 
              pidsToRemove.size(), totalProcesses, GetCacheCount());
    } else {
        LOG_A(LOG_DEBUG, "ProcessResolver: No stale processes found during cleanup");
    }
}


bool ProcessResolver::IsProcessAlive(DWORD pid) {
    // Skip system idle process (PID 0)
    if (pid == 0) {
        return true;
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        return false; // Process no longer exists
    }
    
    DWORD exitCode;
    bool isAlive = true;
    if (GetExitCodeProcess(hProcess, &exitCode)) {
        isAlive = (exitCode == STILL_ACTIVE);
    }
    
    CloseHandle(hProcess);
    return isAlive;
}

