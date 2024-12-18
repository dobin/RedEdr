#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <mutex>

#include "meminfo.h"

TargetInfo g_TargetInfo = TargetInfo();

TargetInfo::TargetInfo() {
}


void TargetInfo::AddMemoryRegion(uint64_t addr, MemoryRegion* region) {
	memoryRegions.add(Range(addr, addr + region->size, region));
}


BOOL TargetInfo::ExistMemoryRegion(uint64_t addr) {
	return memoryRegions.contains(addr);
}


MemoryRegion* TargetInfo::GetMemoryRegion(uint64_t addr) {
	const Range* range = memoryRegions.get(addr);
	if (range != NULL) {
		return (MemoryRegion*)range->data_;
	}
	else {
		return NULL;
	}
}


void TargetInfo::RemoveMemoryRegion(uint64_t addr, size_t size) {
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


void TargetInfo::ClearMemoryRegions() {
	//for (auto& it : memoryRegions) {
	//	delete it.second;
	//}
	//memoryRegions.clear();
}


void TargetInfo::PrintMemoryRegions() {
	for (const auto& it : memoryRegions.ranges_) {
		MemoryRegion* r = (MemoryRegion*)it.data_;
		printf("Entry: %s 0x%llx 0x%llx  %s\n",
			r->name.c_str(),
			r->addr,
			r->size,
			r->protection.c_str()
		);
	}
}


nlohmann::json TargetInfo::ToJson() {
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


std::string TargetInfo::ResolveStr(uint64_t addr) {
	MemoryRegion* r = GetMemoryRegion(addr);
	if (r == NULL) {
		return "Unknown";
	}
	return r->name;
}
