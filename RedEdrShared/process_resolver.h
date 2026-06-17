#pragma once

#include <windows.h>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <chrono>

#include "myprocess.h"


class ProcessResolver {
public:
    ProcessResolver();
    ~ProcessResolver();
    
    // addObject() removed: use getObject() which auto-creates, or insertProcess() for pre-built objects
    BOOL containsObject(DWORD pid);
    Process* getObject(DWORD id);
    void removeObject(DWORD id);

    void ResetData();
    BOOL PopulateAllProcesses();
    void LogCacheStatistics();
    //void RefreshCache();
    void RefreshTargetMatching();

    void SetTargetNames(const std::vector<std::string>& names);
    std::vector<std::string> GetTargetNames() const;  // returns a snapshot copy (thread-safe)
    size_t GetCacheCount();
    
    // Cleanup thread management
    void StartCleanupThread(std::chrono::minutes interval);
    void StopCleanupThread();

private:
	std::vector<std::string> targetProcessNames = {};
    std::unordered_map<DWORD, std::unique_ptr<Process>> cache;
    
    mutable std::mutex cache_mutex;

    // Cleanup thread members
    std::atomic<bool> cleanupThreadRunning{false};
    std::thread cleanupThread;
    std::chrono::minutes cleanupInterval{1};
    
    // Cleanup Helper methods
    void CleanupWorker();
    void CleanupStaleProcesses();
    bool IsProcessAlive(DWORD pid);
};

// Declare a global instance
extern ProcessResolver g_ProcessResolver;
