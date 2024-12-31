#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <mutex>

#include "mem_static.h"


MemStatic g_MemStatic = MemStatic();

MemStatic::MemStatic() {
}


void MemStatic::AddMemoryRegion(uint64_t addr, MemoryRegion* region) {
	memoryRegions.add(Range(addr, addr + region->size, region));
}


BOOL MemStatic::ExistMemoryRegion(uint64_t addr) {
	return memoryRegions.contains(addr);
}


MemoryRegion* MemStatic::GetMemoryRegion(uint64_t addr) {
	const Range* range = memoryRegions.get(addr);
	if (range != NULL) {
		return (MemoryRegion*)range->data_;
	}
	else {
		return NULL;
	}
}


void MemStatic::RemoveMemoryRegion(uint64_t addr, size_t size) {
	for (auto it = memoryRegions.ranges_.begin(); it != memoryRegions.ranges_.end(); ) {
		if (it->contains(addr)) {
			it = memoryRegions.ranges_.erase(it);
		}
		else {
			++it;
		}
	}

	//delete memoryRegions[addr];
	//memoryRegions.erase(addr);
}


void MemStatic::ResetData() {
	memoryRegions.ResetData();
}


void MemStatic::PrintMemoryRegions() {
	printf("Memory Regions: \n");
	for (const auto& it : memoryRegions.ranges_) {
		MemoryRegion* r = (MemoryRegion*)it.data_;
		printf("  %s 0x%llx 0x%llx  %s\n",
			r->name.c_str(),
			r->addr,
			r->size,
			r->protection.c_str()
		);
	}
}


nlohmann::json MemStatic::ToJson() {
	nlohmann::json j;
	for (const auto& it : memoryRegions.ranges_) {
		MemoryRegion* r = (MemoryRegion*)it.data_;

		j.push_back({
			{"name", r->name},
			{"addr", r->addr},
			{"size", r->size},
			{"protection", r->protection}
			});
	}
	return j;
}


std::string MemStatic::ResolveStr(uint64_t addr) {
	MemoryRegion* r = GetMemoryRegion(addr);
	if (r == NULL) {
		return "NOT_IMAGE";
	}
	return r->name;
}
