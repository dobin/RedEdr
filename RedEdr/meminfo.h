#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <mutex>

#include "ranges.h"
#include "json.hpp"



class MemoryRegion {
public:
	MemoryRegion(const std::string& name, uint64_t addr, uint64_t size, std::string protection)
		: name(name), addr(addr), size(size), protection(protection) {}

	std::string name;
	uint64_t addr;
	uint64_t size;
	std::string protection;
};


// Target Info
class TargetInfo {
public:
	TargetInfo();
	void AddMemoryRegion(uint64_t addr, MemoryRegion* region);
	BOOL ExistMemoryRegion(uint64_t addr);
	MemoryRegion* GetMemoryRegion(uint64_t addr);
	void RemoveMemoryRegion(uint64_t addr, size_t size);
	void ClearMemoryRegions();
	void PrintMemoryRegions();
	nlohmann::json ToJson();
	std::string ResolveStr(uint64_t addr);

private:
	RangeSet memoryRegions;
	//std::unordered_map<uint64_t, MemoryRegion*> memoryRegions;
};


extern TargetInfo g_TargetInfo;
