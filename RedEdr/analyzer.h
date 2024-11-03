#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>

#include "json.hpp"
#include "ranges.h"


// Criticality 

enum class Criticality {
	LOW,
	MEDIUM,
	HIGH
};
std::string CriticalityToString(Criticality c);


class CriticalityManager {
private:
    Criticality currentCriticality;

public:
    CriticalityManager() : currentCriticality(Criticality::LOW) {}

    void set(Criticality newCriticality) {
        if (newCriticality > currentCriticality) {
            currentCriticality = newCriticality;
        }
    }

    Criticality get() const {
        return currentCriticality;
    }
};


// Memory Region

class MemoryRegion {
public:
    MemoryRegion(const std::string& name, uint64_t addr, uint64_t size, std::string protection)
        : name(name), addr(addr), size(size), protection(protection) {}

    std::string name;
    uint64_t addr;
    uint64_t size;
	std::string protection;
};

uint64_t AlignToPage(uint64_t addr);

// Target Info
class TargetInfo {
public:
	TargetInfo() {}
	
	void AddMemoryRegion(uint64_t addr, MemoryRegion* region) {
		//memoryRegions[addr] = region;
		memoryRegions.add(Range(addr, addr + region->size, region));
	}

	BOOL ExistMemoryRegion(uint64_t addr) {
		return memoryRegions.contains(addr);
		//auto it = memoryRegions.find(addr);
		//return it != memoryRegions.end() ? TRUE : FALSE;
	}

	MemoryRegion* GetMemoryRegion(uint64_t addr) {
		//return memoryRegions[addr];
		return (MemoryRegion*) memoryRegions.get(addr).data_;
	}

	void RemoveMemoryRegion(uint64_t addr) {
		//delete memoryRegions[addr];
		//memoryRegions.erase(addr);
	}

	void ClearMemoryRegions() {
		//for (auto& it : memoryRegions) {
		//	delete it.second;
		//}
		//memoryRegions.clear();
	}

	void PrintMemoryRegions() {
		for (const auto& it : memoryRegions.ranges_) {
			MemoryRegion* r = (MemoryRegion*) it.data_;
			printf("Entry: %s 0x%llx 0x%llx  %s\n",
				r->name.c_str(),
				r->addr,
				r->size,
				r->protection.c_str()
			);
		}
	}

private:
	RangeSet memoryRegions;
	//std::unordered_map<uint64_t, MemoryRegion*> memoryRegions;
};


// Analyzer

class MyAnalyzer {
public:
	void AnalyzeEventJson(nlohmann::json j);
	void AnalyzeEventStr(std::string eventStr);
    void AnalyzerNewDetection(Criticality c, std::string s);

	std::string GetAllDetectionsAsJson();
	void ResetData();

	// 
    std::vector<std::string> detections;
	TargetInfo targetInfo;
};


DWORD WINAPI AnalyzerThread(LPVOID param);
int InitializeAnalyzer(std::vector<HANDLE>& threads);
void StopAnalyzer();

extern MyAnalyzer g_Analyzer;
