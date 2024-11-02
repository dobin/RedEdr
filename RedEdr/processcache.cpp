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

#include "processcache.h"
#include "utils.h"
#include "processinfo.h"
#include "config.h"
#include "eventproducer.h"

ProcessCache g_ProcessCache;
std::mutex cache_mutex;


ProcessCache::ProcessCache() {

}

// Add an object to the cache
void ProcessCache::addObject(DWORD id, const Process& obj) {
    cache_mutex.lock();
    cache[id] = obj;
    cache_mutex.unlock();
}

BOOL ProcessCache::containsObject(DWORD pid) {
    cache_mutex.lock();
    auto it = cache.find(pid);
    cache_mutex.unlock();
    if (it != cache.end()) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

// Get an object from the cache
Process* ProcessCache::getObject(DWORD id) {
    cache_mutex.lock();
    auto it = cache.find(id);
    cache_mutex.unlock();
    if (it != cache.end()) {
        return &it->second; // Return a pointer to the object
    }

    // Does not exist, create and add to cache
    Process* process = MakeProcess(id, g_config.targetExeName); // in here cache.cpp...

    // every new pid comes through here
    // if everything worked
    // if we observe it, we need to DLL inject it too
    //if (process->observe && g_config.do_udllinjection) {
    //    remote_inject(pid);
    //}

    if (process->observe) {
        AugmentProcess(id, process);
        std::wstring o = format_wstring(L"type:peb;time:%lld;id:%lld;parent_pid:%lld;image_path:%ls;commandline:%ls;working_dir:%ls;is_debugged:%d;is_protected_process:%d;is_protected_process_light:%d;image_base:0x%p",
            get_time(),
            process->id,
            process->parent_pid,
            process->image_path.c_str(),
            process->commandline.c_str(),
            process->working_dir.c_str(),
            process->is_debugged,
            process->is_protected_process,
            process->is_protected_process_light,
            process->image_base
        );
        g_EventProducer.do_output(o);


        PrintLoadedModules(id, process);
    }

    cache_mutex.lock();
    cache[id] = *process;
    cache_mutex.unlock();
    return &cache[id];
}

BOOL ProcessCache::observe(DWORD id) {
    Process* p = getObject(id);
    if (p != NULL) {
        return p->doObserve();
    }
    return FALSE;
}

// Remove an object from the cache
void ProcessCache::removeObject(DWORD id) {
    cache_mutex.lock();
    cache.erase(id);
    cache_mutex.unlock();
}

void ProcessCache::removeAll() {
    cache_mutex.lock();
    cache.clear();
    cache_mutex.unlock();
}
