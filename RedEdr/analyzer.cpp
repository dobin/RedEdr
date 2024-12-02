#include <iostream>
#include <sstream>
#include <vector>
#include <locale>
#include <codecvt>

#include "eventproducer.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"
#include "analyzer.h"


HANDLE analyzer_thread;

Analyzer g_Analyzer;


// Private
std::string CriticalityToString(Criticality c);
void PrintEvent(nlohmann::json j);
uint64_t AlignToPage(uint64_t addr);
std::string getLastTwoFields(const std::string& input);


void Analyzer::AnalyzerNewDetection(nlohmann::json& j, Criticality c, std::string s) {
    std::string o = CriticalityToString(c) + ": " + s;
    detections.push_back(o);
    j["detections"] += o;
    //LOG_A(LOG_INFO, "%s", o.c_str());
    //LOG_A(LOG_INFO, "%s", j.dump().c_str());
}


std::string sus_protect(std::string protect) {
    std::string lastprotect = getLastTwoFields(protect);

    // RW->RX for shellcode loader
    if (lastprotect.find("RW-;R-X") != std::string::npos) {
        return std::string("Sus VirtualProtect history RW->RX: ") + protect;
    } else if (lastprotect.find("RWX;R-X") != std::string::npos) {
        return std::string("Sus VirtualProtect history RWX->RX: ") + protect;
    
    // RX->RW for memory encryption
    } else if (lastprotect.find("R-X;RWX") != std::string::npos) {
        return std::string("Sus VirtualProtect history RX->RWX: ") + protect;
    } else if (lastprotect.find("R-X;RW-") != std::string::npos) {
        return std::string("Sus VirtualProtect history RX->RW: ") + protect;
    
    // NOACCESS shenanigans for memory encryption
    } else if (lastprotect.find("R-X;NOACCESS") != std::string::npos) {
        return std::string("Sus VirtualProtect history RX->NOACCESS: ") + protect;
    }
    return "";
}


void Analyzer::AnalyzeEventJson(nlohmann::json j) {
    BOOL printed = FALSE;

    if (j["type"] == "kernel") {
		num_kernel += 1;
    } 
    else if (j["type"] == "dll") {
		num_dll += 1;
    }
    else if (j["type"] == "etw") {
        if (j["provider_name"] == "Microsoft-Windows-Threat-Intelligence") {
            num_etwti += 1;
        }
        else {
            num_etw += 1;
        }
    }

    if (!j.contains("type")) {
        LOG_A(LOG_WARNING, "No type? %s", j.dump().c_str());
        return;
    }

    if (j["type"] == "loaded_dll") {
        for (const auto& it: j["dlls"]) {
            uint64_t addr = std::stoull(it["addr"].get<std::string>(), nullptr, 16);
            uint64_t size = std::stoull(it["size"].get<std::string>(), nullptr, 10);
            std::string protection = "???";
            std::string name = "loaded_dll:" + it["name"];

			addr = AlignToPage(addr);
            // always add, as its early in the process without collisions hopefully
            MemoryRegion* region = new MemoryRegion(name, addr, size, protection);
            targetInfo.AddMemoryRegion(addr, region);
        }
    }

    if (j["type"] == "dll" && j["func"] == "AllocateVirtualMemory") {
        uint64_t addr = std::stoull(j["addr"].get<std::string>(), nullptr, 16);
        uint64_t size = std::stoull(j["size"].get<std::string>(), nullptr, 10);
        std::string protection = j["protect"];

        //std::string jsonString = j.dump();
        //std::cout << "Compact JSON: " << jsonString << std::endl;

        addr = AlignToPage(addr);
        MemoryRegion* memoryRegion = targetInfo.GetMemoryRegion(addr);
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
            targetInfo.AddMemoryRegion(addr, memoryRegion);
        }

        if (j["handle"] != "0xffffffffffffffff") {
            std::stringstream ss;
            ss << "AllocateVirtualMemory in foreign process " << j["handle"].get<std::string>();
            AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
        }
    }

    if (j["type"] == "dll" && j["func"] == "WriteVirtualMemory") {
        if (j["handle"] != "0xffffffffffffffff") {
            std::stringstream ss;
            ss << "WriteVirtualMemory in foreign process " << j["handle"].get<std::string>();
            AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
        }
    }

    if (j["type"] == "dll" && j["func"] == "CreateRemoteThread") {
        if (j["handle"] != "0xffffffffffffffff") {
            std::stringstream ss;
            ss << "CreateRemoteThread in foreign process " << j["handle"].get<std::string>();
            AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
        }
    }


    if (j["type"] == "dll" && j["func"] == "FreeVirtualMemory") {
        uint64_t addr = std::stoull(j["addr"].get<std::string>(), nullptr, 16);
        uint64_t size = std::stoull(j["size"].get<std::string>(), nullptr, 10);

        MemoryRegion* memoryRegion = targetInfo.GetMemoryRegion(addr);
        if (memoryRegion != NULL) {
            // do not remove, but indicate it has been freed
            //targetInfo.RemoveMemoryRegion(addr, size);
            memoryRegion->protection += ";freed";
        }
        else {
            //LOG_A(LOG_WARNING, "Free a non-allocated");
            // No add as its free anyway?
        }
    }

    if (j["type"] == "dll" && j["func"] == "ProtectVirtualMemory") {
        uint64_t addr = std::stoull(j["addr"].get<std::string>(), nullptr, 16);
        uint64_t size = std::stoull(j["size"].get<std::string>(), nullptr, 10);
        std::string protection = j["protect"];
        std::string name = "Protected";

        addr = AlignToPage(addr);
        // Check if exists
        MemoryRegion* memoryRegion = targetInfo.GetMemoryRegion(addr);
        if (memoryRegion == NULL) {
			//LOG_A(LOG_WARNING, "ProtectVirtualMemory region 0x%llx not found. Adding.",
            //    addr);
            MemoryRegion* region = new MemoryRegion(name, addr, size, protection);
            targetInfo.AddMemoryRegion(addr, region);
        }
		else {
			// Update protection
			MemoryRegion* region = targetInfo.GetMemoryRegion(addr);
			region->protection += ";" + protection;
			//LOG_A(LOG_INFO, "ProtectVirtualMemory: %s 0x%llx 0x%llx %s",
			//	name.c_str(), addr, size, protection.c_str());

            std::string sus = sus_protect(region->protection);
            if (sus != "") {
                AnalyzerNewDetection(j, Criticality::HIGH, sus);
            }
        }
    }

    // Allocate or map memory with RWX protection
    if (j.value("protect", "") == "RWX") {
        j["detection"] += "RWX";
        Criticality c = Criticality::HIGH;

        std::stringstream ss;
        ss << "Function " << j["func"].get<std::string>() << " doing RWX";
        ss << " with size " << j["size"].get<std::string>();

        if (j["func"] == "MapViewOfSection") {
            ss << " SectionHandle " << j["section_handle"].get<std::string>();
            c = Criticality::LOW;
        }
        else if (j["func"] == "ProtectVirtualMemory") {
            //ss << " SectionHandle: " << j["section_handle"].get<std::string>();
            c = Criticality::HIGH;
        }
        AnalyzerNewDetection(j, c, ss.str());
        printed = TRUE;
    }

    int idx = 0;
    // Check callstack
    if (j.contains("callstack") && j["callstack"].is_array()) {
        for (const auto& callstack_entry : j["callstack"]) {
            CriticalityManager cm;
            std::stringstream ss;
            BOOL print2 = FALSE;

            // Callstack entry from RWX region
            if (callstack_entry["protect"] == "RWX") {
                ss << "High: RWX section, ";
                j["detection"] += "RWX";
                cm.set(Criticality::HIGH);
                print2 = TRUE;
            }

            // Callstack entry from non-image region
            if (callstack_entry["type"] != "IMAGE") { // MEM_IMAGE
                if (callstack_entry["type"] == "MAPPED") { // MEM_MAPPED
                    ss << "Low: MEM_MAPPED section, ";
                    j["detection"] += "MEM_MAPPED";
                    cm.set(Criticality::LOW);
                    print2 = TRUE;
                }
                else if (callstack_entry["type"] == "PRIVATE") { // MEM_PRIVATE, unbacked!
                    ss << "High: MEM_PRIVATE section, ";
                    j["detection"] += "MEM_PRIVATE";
                    cm.set(Criticality::HIGH);
                    print2 = TRUE;
                }
                else {
                    ss << "Unknown: other section, ";
                    j["detection"] += "MEM_OTHER";  // TODO: add hex
                    cm.set(Criticality::MEDIUM);
                    print2 = TRUE;
                }
            }

            if (print2) {
                if (!printed) {
                    std::stringstream x;
                    x << "Function " << j["func"].get<std::string>();
                    printed = TRUE;
                }

                std::stringstream s;
                s << "Suspicious callstack " << idx << " of " << j["callstack"].size() << " by " << j["func"].get<std::string>();
                /*if (j["func"] == "ProtectVirtualMemory") {
                    s << " addr " << j["addr"].get<std::string>();
                    s << " protect " << j["protect"].get<std::string>();
                }*/
                s << " addr " << callstack_entry["addr"].get<std::string>();
                s << " protect " << callstack_entry["protect"].get<std::string>();
                s << " type " << callstack_entry["type"].get<std::string>();
                AnalyzerNewDetection(j, cm.get(), s.str());
            }
            idx += 1;
        }
    }

    json_entries.push_back(j);
}


void Analyzer::AnalyzeEventStr(std::string eventStr) {
    //std::cout << L"Processing: " << eventStr << std::endl;
    nlohmann::json j;
    try
    {
        j = nlohmann::json::parse(eventStr);
    }
    catch (const nlohmann::json::exception& e)
    {
        LOG_A(LOG_WARNING, "JSON Parser Exception msg: %s", e.what());
        LOG_A(LOG_WARNING, "JSON Parser Exception event: %s", eventStr.c_str());
        return;
    }

    AnalyzeEventJson(j);
}


void Analyzer::AnalyzeNewEvents(std::vector<std::string> events) {
    for (std::string& entry : events) {
        g_Analyzer.AnalyzeEventStr(entry);
    }
}


void Analyzer::ResetData() {
    detections.clear();
}


std::string Analyzer::GetAllDetectionsAsJson() {
    nlohmann::json jsonArray = detections;
    return jsonArray.dump();
}


size_t Analyzer::GetDetectionsCount() {
    return detections.size();
}


std::string Analyzer::GetAllAsJson() {
    return nlohmann::json(json_entries).dump();
    //output << ReplaceAllA(*it, "\\", "\\\\");
}


void Analyzer::SaveToFile() {
    std::string data = GetAllAsJson();
    std::string filename = "C:\\RedEdr\\Data\\" + get_time_for_file() + ".events.json";
    write_file(filename, data);
}


// Module functions

DWORD WINAPI AnalyzerThread(LPVOID param) {
    LOG_A(LOG_INFO, "!Analyzer: Start thread");
    size_t arrlen = 0;
    std::unique_lock<std::mutex> lock(g_EventProducer.analyzer_shutdown_mtx);

    while (true) {
        // Block for new events
        g_EventProducer.cv.wait(lock, [] { return g_EventProducer.HasMoreEvents() || g_EventProducer.done; });
        if (g_EventProducer.done) {
            break;
        }
        // get em events
        std::vector<std::string> new_entries = g_EventProducer.GetEvents();
        g_Analyzer.AnalyzeNewEvents(new_entries);
    }

    LOG_A(LOG_INFO, "!Analyzer: Exit thread");
    return 0;
}


int InitializeAnalyzer(std::vector<HANDLE>& threads) {
    analyzer_thread = CreateThread(NULL, 0, AnalyzerThread, NULL, 0, NULL);
    if (analyzer_thread == NULL) {
        LOG_A(LOG_ERROR, "WEB: Failed to create thread for webserver");
        return 1;
    }
    threads.push_back(analyzer_thread);
    return 0;
}


void StopAnalyzer() {
    if (analyzer_thread != NULL) {
        g_EventProducer.Stop();
    }
}




/** Utils **/


std::string CriticalityToString(Criticality c) {
    switch (c) {
    case Criticality::LOW:   return "LOW";
    case Criticality::MEDIUM: return "MEDIUM";
    case Criticality::HIGH:  return "HIGH";
    default:          return "UNKNOWN";
    }
}



void PrintEvent(nlohmann::json j) {
    std::string output = j.dump();
    LOG_A(LOG_INFO, "Event: %s", output.c_str());
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