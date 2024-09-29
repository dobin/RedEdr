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

#include "cache.h"
#include "utils.h"
#include "procinfo.h"
#include "config.h"
#include "output.h"

Cache g_cache;

Cache::Cache() {

}

// Add an object to the cache
void Cache::addObject(DWORD id, const Process& obj) {
    cache[id] = obj;
}

BOOL Cache::containsObject(DWORD pid) {
    auto it = cache.find(pid);
    if (it != cache.end()) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

// Get an object from the cache
Process* Cache::getObject(DWORD id) {
    auto it = cache.find(id);
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
        do_output(o);

        // Broken atm
        //PrintLoadedModules(hProcess, process);
    }

    cache[id] = *process;
    return &cache[id];
}

BOOL Cache::observe(DWORD id) {
    Process* p = getObject(id);
    if (p != NULL) {
        return p->doObserve();
    }
    return FALSE;
}

// Remove an object from the cache
void Cache::removeObject(DWORD id) {
    cache.erase(id);
}


void test() {
    //Cache cache;

    // Try to retrieve an object (which will be created if not found)
    Process* obj = g_cache.getObject(9592); // admin, c:\temp
    if (obj) {
        obj->display();
    }

    /*obj = cache.getObject(2460);
    if (obj) {
        obj->display();
    }*/
}
