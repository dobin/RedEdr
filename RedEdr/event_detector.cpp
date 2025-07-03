#include <iostream>
#include <sstream>
#include <vector>
#include <locale>
#include <codecvt>

#include "mem_dynamic.h"
#include "event_detector.h"
#include "config.h"


/* Attempts to identify malicious behaviour based on the events
 * No process query or similar sould be performed here, 
 * only accessing the events themselves.
 */

uint64_t AlignToPage(uint64_t addr);
std::string getLastTwoFields(const std::string& input);

EventDetector g_EventDetector = EventDetector();


std::string sus_protect(std::string protect) {
    std::string lastprotect = getLastTwoFields(protect);

    // RW->RX for shellcode loader
    if (lastprotect.find("RW-;R-X") != std::string::npos) {
        return std::string("Sus VirtualProtect history RW->RX: ") + protect;
    }
    else if (lastprotect.find("RWX;R-X") != std::string::npos) {
        return std::string("Sus VirtualProtect history RWX->RX: ") + protect;

        // RX->RW for memory encryption
    }
    else if (lastprotect.find("R-X;RWX") != std::string::npos) {
        return std::string("Sus VirtualProtect history RX->RWX: ") + protect;
    }
    else if (lastprotect.find("R-X;RW-") != std::string::npos) {
        return std::string("Sus VirtualProtect history RX->RW: ") + protect;

        // NOACCESS shenanigans for memory encryption
    }
    else if (lastprotect.find("R-X;NOACCESS") != std::string::npos) {
        return std::string("Sus VirtualProtect history RX->NOACCESS: ") + protect;
    }
    return "";
}


void EventDetector::AnalyzerNewDetection(nlohmann::json& j, Criticality c, std::string s) {
    std::string o = CriticalityToString(c) + ": " + s;
    detections.push_back(o);
    j["detections"] += o;

    if (g_Config.debug) {
        LOG_A(LOG_INFO, "New Detection: %s", o.c_str());
    }
    //LOG_A(LOG_INFO, "%s", o.c_str());
    //LOG_A(LOG_INFO, "%s", j.dump().c_str());
}


void EventDetector::ScanEventForDetections(nlohmann::json& j) {
    try {
        if (!j.contains("type") || !j["type"].is_string()) {
            return; // Invalid event format
        }
        
        if (j["type"] == "etw") {
            // ETW-TI
            if (j.contains("provider_name") && j["provider_name"] == "f4e1897c-bb5d-5668-f1d8-040f4d8dd344") {
                if (j.contains("event") && j["event"] == "KERNEL_THREATINT_TASK_PROTECTVM") {
                    if (j.contains("ProtectionMask") && j["ProtectionMask"] == "RWX") {
                        std::stringstream ss;
                        ss << "ProtectMemory with RWX at addr " << j["BaseAddress"].get<std::uint64_t>();
                        AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
                    }
                }

                // Callstack
                if (j.contains("stack_trace") && j["stack_trace"].is_array()) {
                    for (const auto& callstack_entry : j["stack_trace"]) {
                        if (callstack_entry.contains("addr_info") && callstack_entry["addr_info"] == "NOT_IMAGE") {
                            AnalyzerNewDetection(j, Criticality::HIGH, "Callstack contains non-image entry");
                        }
                    }
                }
            }
        }
        if (j["type"] == "dll") {
            if (j.contains("func") && j["func"].is_string()) {
                std::string funcName = j["func"].get<std::string>();
                
                if (funcName == "NtAllocateVirtualMemory") {
                    if (j.contains("handle") && j["handle"].is_number() && j["handle"].get<int64_t>() != -1) {
                        std::stringstream ss;
                        ss << "NtAllocateVirtualMemory in foreign process " << j["handle"].get<uint64_t>();
                        AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
                    }
                }
                else if (funcName == "NtWriteVirtualMemory") {
                    if (j.contains("handle") && j["handle"].is_number() && j["handle"].get<int64_t>() != -1) {
                        std::stringstream ss;
                        ss << "NtWriteVirtualMemory in foreign process " << j["handle"].get<uint64_t>();
                        AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
                    }
                }
                else if (funcName == "NtCreateRemoteThread") {
                    if (j.contains("handle") && j["handle"].is_number() && j["handle"].get<int64_t>() != -1) {
                        std::stringstream ss;
                        ss << "NtCreateRemoteThread in foreign process " << j["handle"].get<uint64_t>();
                        AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
                    }
                }
                else if (funcName == "NtProtectVirtualMemory") {
                    // Check for simple RWX
                    if (j.contains("protect") && j["protect"].is_string() && j["protect"].get<std::string>() == "RWX") {
                        if (j.contains("addr") && j["addr"].is_number()) {
                            std::stringstream ss;
                            ss << "NtProtectVirtualMemory with RWX at addr " << j["addr"].get<uint64_t>();
                            AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
                        }
                    }

                    // Check if the region has been suspiciously protected before (RW<->RX)
                    if (j.contains("addr") && j["addr"].is_number()) {
                        uint64_t addr = j["addr"].get<uint64_t>();
                        MemoryRegion* region = memDynamic.GetMemoryRegion(addr);
                        if (region != NULL) {
                            std::string sus = sus_protect(region->protection);
                            if (sus != "") {
                                AnalyzerNewDetection(j, Criticality::HIGH, sus);
                            }
                        }
                    }
                }
            }
        }
        if (j["func"] == "NtMapViewOfSection") {
            // Check for simple RWX
            if (j.value("protect", "") == "RWX") {
                std::stringstream ss;
                ss << "NtMapViewOfSection with RWX at addr " << j["addr"].get<uint64_t>();
                AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
            }
        }

        // Check Injecte-DLL function callstack
        bool non_image_callstack = false;
        if (j.contains("callstack") && j["callstack"].is_array()) {
            for (const auto& callstack_entry : j["callstack"]) {
                // Callstack entry from RWX region
                if (callstack_entry["protect"] == "MEM_RWX") {
                    AnalyzerNewDetection(j, Criticality::HIGH, "RWX");
                }

                // Callstack entry from non-image region
                if (callstack_entry["type"] != "IMAGE") { // MEM_IMAGE
					non_image_callstack = true;
                }
            }
        }
        if (non_image_callstack) {
            AnalyzerNewDetection(j, Criticality::HIGH, "Non-image in callstack");
        }
    }
    catch (const nlohmann::json::exception& e) {
        LOG_A(LOG_ERROR, "JSON error in ScanEventForDetections: %s", e.what());
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "Error in ScanEventForDetections: %s", e.what());
    }
}


void EventDetector::ScanEventForMemoryChanges(nlohmann::json& j) {
    try {
        if (!j.contains("type") || !j["type"].is_string()) {
            return; // Invalid event format
        }

        // Loaded dll's
        if (j["type"] == "loaded_dll") {
            if (j.contains("dlls") && j["dlls"].is_array()) {
                for (const auto& it : j["dlls"]) {
                    if (it.contains("addr") && it.contains("size") && it.contains("name") &&
                        it["addr"].is_number() && it["size"].is_number() && it["name"].is_string()) {
                        uint64_t addr = it["addr"].get<uint64_t>();
                        uint64_t size = it["size"].get<uint64_t>();
                        std::string protection = "???";
                        std::string name = "loaded_dll:" + it["name"].get<std::string>();

                        addr = AlignToPage(addr);
                        // always add, as its early in the process without collisions hopefully
                        MemoryRegion* region = new MemoryRegion(name, addr, size, protection);
                        memDynamic.AddMemoryRegion(addr, region);
                    }
                }
            }
        }

        // From injected dll
        if (j["type"] == "dll") {
            if (j["func"] == "NtAllocateVirtualMemory") {
                uint64_t addr = j["addr"].get<uint64_t>();
                uint64_t size = j["size"].get<uint64_t>();
                std::string protection = j["protect"];

                //std::string jsonString = j.dump();
                //std::cout << "Compact JSON: " << jsonString << std::endl;

                addr = AlignToPage(addr);
                MemoryRegion* memoryRegion = memDynamic.GetMemoryRegion(addr);
                if (memoryRegion != NULL) {
                    //LOG_A(LOG_WARNING, "Allocate Memory ALREADY FOUND??! 0x%llx %llu end:0x%llx",
                    //   addr, size, addr+size);
                    //LOG_A(LOG_INFO, "              : %s 0x%llx %llu end:0x%llx %s",
                    //    region->name.c_str(), region->addr, region->size,
                    //    region->addr + region->size,
                    //    region->protection.c_str());*/
                    memoryRegion->protection += ";Alloc:" + protection;
                }
                else {
                    //LOG_A(LOG_WARNING, "Allocate Memory new: 0x%llx %llu",
                    //    addr, size);
                    memoryRegion = new MemoryRegion("Allocated", addr, size, protection);
                    memDynamic.AddMemoryRegion(addr, memoryRegion);
                }

                if (j["func"] == "NtFreeVirtualMemory") {
                    uint64_t addr = j["addr"].get<uint64_t>();
                    uint64_t size = j["size"].get<uint64_t>();

                    MemoryRegion* memoryRegion = memDynamic.GetMemoryRegion(addr);
                    if (memoryRegion != NULL) {
                        // do not remove, but indicate it has been freed
                        //memDynamic.RemoveMemoryRegion(addr, size);
                        memoryRegion->protection += ";freed";
                    }
                    else {
                        //LOG_A(LOG_WARNING, "Free a non-allocated");
                        // No add as its free anyway?
                    }
                }
            }

            if (j["func"] == "NtProtectVirtualMemory") {
                uint64_t addr = j["addr"].get<uint64_t>();
                uint64_t size = j["size"].get<uint64_t>();
                std::string protection = j["protect"];
                std::string name = "Protected";

                addr = AlignToPage(addr);
                // Check if exists
                MemoryRegion* memoryRegion = memDynamic.GetMemoryRegion(addr);
                if (memoryRegion == NULL) {
                    //LOG_A(LOG_WARNING, "ProtectVirtualMemory region 0x%llx not found. Adding.",
                    //    addr);
                    MemoryRegion* region = new MemoryRegion(name, addr, size, protection);
                    memDynamic.AddMemoryRegion(addr, region);
                }
                else {
                    // Update protection
                    MemoryRegion* region = memDynamic.GetMemoryRegion(addr);
                    region->protection += ";" + protection;
                    //LOG_A(LOG_INFO, "ProtectVirtualMemory: %s 0x%llx 0x%llx %s",
                    //	name.c_str(), addr, size, protection.c_str());
                }
            }
        }
    }
    catch (const nlohmann::json::exception& e) {
        LOG_A(LOG_ERROR, "JSON error in ScanEventForMemoryChanges: %s", e.what());
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "Error in ScanEventForMemoryChanges: %s", e.what());
    }
}


void EventDetector::ResetData() {
	detections.clear();
	memDynamic.ResetData();
}


/* Utils */

std::string CriticalityToString(Criticality c) {
    switch (c) {
    case Criticality::LOW:   return "LOW";
    case Criticality::MEDIUM: return "MEDIUM";
    case Criticality::HIGH:  return "HIGH";
    default:          return "UNKNOWN";
    }
}


std::string EventDetector::GetAllDetectionsAsJson() {
    nlohmann::json jsonArray = detections;
    return jsonArray.dump();
}


size_t EventDetector::GetDetectionsCount() {
    return detections.size();
}


MemStatic* EventDetector::GetTargetMemoryChanges() {
	return &memDynamic;
}


uint64_t AlignToPage(uint64_t addr) {
    constexpr uint64_t pageSize = 4096;
    return addr & ~(pageSize - 1);
}


std::string getLastTwoFields(const std::string& input) {
    // Find the last semicolon
    size_t lastSemicolon = input.rfind(';');
    if (lastSemicolon == std::string::npos) {
        return "";  // No semicolons found, return empty
    }

    // Find the second-to-last semicolon by searching before the last semicolon
    size_t secondLastSemicolon = input.rfind(';', lastSemicolon - 1);
    if (secondLastSemicolon == std::string::npos) {
        return "";  // Less than two fields, return empty
    }

    // Extract substring from the second-to-last semicolon to the end of the string
    return input.substr(secondLastSemicolon + 1);
}