#include <Windows.h>
#include <stdio.h>
#include "uthash.h"
#include <psapi.h>

#include "objcache.h"
#include "logging.h"

struct my_hashmap* map = NULL;
HANDLE mutex;
wchar_t* target_name = NULL;


void set_target_name(wchar_t* t) {
    target_name = t;
}


void objcache_init() {
    mutex = CreateMutex(NULL, FALSE, NULL);
}


struct my_hashmap* get_obj(int pid) {
    struct my_hashmap* obj = NULL;
    obj = has_obj(pid);
    if (obj != NULL) {
        return obj;
    }
    
    // Add new
    HANDLE hProcess;
    WCHAR exePath[MAX_PATH];
    int observe = 0;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProcess == NULL) {
        // We dont care
        //LOG_W(LOG_INFO, L"Could not open process %lu error %lu\n", pid, GetLastError());
    }
    else {
        if (target_name != NULL) {
            if (GetModuleFileNameEx(hProcess, NULL, exePath, MAX_PATH)) {
                wchar_t* result = wcsstr(exePath, target_name);
                if (result) {
                    LOG_W(LOG_INFO, L"Objcache: observe process %lu executable path: %s\n", pid, exePath);
                    //LOG_W(LOG_INFO, L"Substring found in: %s\n", exePath);
                    observe = 1;
                }
                else {
                    //LOG_W(LOG_INFO, L"Substring not found %lu: %s\n", pid, exePath);
                    observe = 0;
                }
            }
            else {
                //LOG_W(LOG_INFO, L"Failed to get executable path: %lu\n", GetLastError());
            }
        }
        CloseHandle(hProcess);
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
    struct my_hashmap* entry = NULL, * tmp = NULL;
    HASH_ITER(hh, map, entry, tmp) {
        HASH_DEL(map, entry);
        free(entry);
    }
}

