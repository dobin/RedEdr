#pragma once

#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <mutex>

#include "ranges.h"
#include "myprocess.h"


std::wstring GetProcessName(HANDLE hProcess);
BOOL InitProcessQuery();
DWORD FindProcessIdByName(const std::wstring& processName);

struct ProcessAddrInfoRet {
    std::string name;
    PVOID base_addr;

    // Original?
    PVOID allocation_base;
    size_t region_size;
    DWORD allocation_protect;

    DWORD state;
    DWORD protect;
    DWORD type;

    std::string stateStr;
    std::string protectStr;
    std::string typeStr;
};
ProcessAddrInfoRet ProcessAddrInfo(HANDLE hProcess, PVOID address);


struct ProcessPebInfoRet {
    std::string image_path;
    std::string commandline;
    std::string working_dir;
    DWORD parent_pid;
    DWORD is_debugged;
    DWORD is_protected_process;
    DWORD is_protected_process_light;
    uint64_t image_base;
};
ProcessPebInfoRet ProcessPebInfo(HANDLE hProcess);


struct ProcessLoadedDll {
    uint64_t dll_base;
    ULONG size;
    std::string name;
};
std::vector<ProcessLoadedDll> ProcessEnumerateModules(HANDLE hProcess);


struct ModuleSection {
public:
    ModuleSection(const std::string& name, uint64_t addr, uint64_t size, std::string protection)
        : name(name), addr(addr), size(size), protection(protection) {}

    std::string name;
    uint64_t addr;
    uint64_t size;
    std::string protection;
};
std::vector<ModuleSection> EnumerateModuleSections(HANDLE hProcess, LPVOID moduleBase);

