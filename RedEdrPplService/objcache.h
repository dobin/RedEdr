#pragma once

#include "uthash.h"
#include <psapi.h>
#include <vector>
#include <string>

// Define a struct for the hashmap
struct my_hashmap {
    int key;            // Key (can be any type, just using int for simplicity)
    int value;  // Value
    UT_hash_handle hh;  // Hash handle for uthash
};

void set_target_names(const std::vector<std::string>& targets);
struct my_hashmap* get_obj(int pid);
struct my_hashmap* add_obj(int pid, int observe);
void objcache_init();
struct my_hashmap* has_obj(int key);
void clean_obj();
bool match_process(std::wstring exePath);
void RefreshProcessMatching();