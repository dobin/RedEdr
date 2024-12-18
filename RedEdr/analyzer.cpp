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
#include "processinfo.h"
#include "analyzer.h"
#include "processcache.h"


HANDLE analyzer_thread;

Analyzer g_Analyzer;


// Private
std::string CriticalityToString(Criticality c);
void PrintEvent(nlohmann::json j);
uint64_t AlignToPage(uint64_t addr);
std::string getLastTwoFields(const std::string& input);


Analyzer::Analyzer() {
    GenerateNewTraceId();
}


void Analyzer::AnalyzerNewDetection(nlohmann::json& j, Criticality c, std::string s) {
    std::string o = CriticalityToString(c) + ": " + s;
    detections.push_back(o);
    j["detections"] += o;

	if (g_config.debug) {
		LOG_A(LOG_INFO, "New Detection: %s", o.c_str());
	}
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


void AugmentAddresses(nlohmann::json& j) {
    if (j.contains("callstack") && j["callstack"].is_array()) {
        for (auto& callstack_entry : j["callstack"]) {
			if (callstack_entry.contains("addr")) {
				uint64_t addr = callstack_entry["addr"].get<uint64_t>();
				std::string symbol = g_TargetInfo.ResolveStr(addr);
				callstack_entry["addr_info"] = symbol;

                // log
				if (g_config.debug) {
					LOG_A(LOG_INFO, "Addr 0x%llx Symbol: %s", 
                        addr,
                        symbol.c_str());
				}
            }
        }
    }
}


void Analyzer::PrintEvent(nlohmann::json j) {
    // Output accordingly
    if (g_config.hide_full_output) {
        if (event_count >= 100) {
            if (event_count % 100 == 0) {
                std::wcout << L"O";
            }
        }
        else if (event_count >= 10) {
            if (event_count % 10 == 0) {
                std::wcout << L"o";
            }
        }
        else {
            std::wcout << L".";
        }
    }
    else {
        std::cout << j.dump() << "\n";
    }
}


void Analyzer::AnalyzeEventJson(nlohmann::json& j) {
    j["id"] = json_entries.size();
    j["trace_id"] = trace_id;

    // Sanity check
    if (!j.contains("type")) {
        LOG_A(LOG_WARNING, "No type? %s", j.dump().c_str());
        return;
    }

    // Stats
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

    // augment process information the first time
    if (!j.contains("pid")) {
        //LOG_A(LOG_WARNING, "No pid? %s", j.dump().c_str());
    }
    else {
        Process* process = g_ProcessCache.getObject(j["pid"].get<DWORD>());
        if (process->augmented == 0) {
            process->augmented++;
            AugmentProcess(j["pid"].get<DWORD>(), process);
            std::wstring o = format_wstring(L"{\"type\":\"peb\",\"time\":%lld,\"id\":%lld,\"parent_pid\":%lld,\"image_path\":\"%s\",\"commandline\":\"%s\",\"working_dir\":\"%s\",\"is_debugged\":%d,\"is_protected_process\":%d,\"is_protected_process_light\":%d,\"image_base\":%llu}",
                get_time(),
                process->id,
                process->parent_pid,
                JsonEscape2(process->image_path.c_str()).c_str(),
                JsonEscape2(process->commandline.c_str()).c_str(),
                JsonEscape2(process->working_dir.c_str()).c_str(),
                process->is_debugged,
                process->is_protected_process,
                process->is_protected_process_light,
                process->image_base
            );
            g_EventProducer.do_output(o);
        }
    }

    // additional checks based on counted events
    if (json_entries.size() == 32) {
        if (j.contains("pid")) {
            DWORD pid = j["pid"].get<DWORD>();
            //QueryProcessInfo(pid, NULL);
        }
    }

    // Augment with memory info
    AugmentAddresses(j);

    // Memory changes
    ExtractMemoryInfo(j);
    //targetMemoryChanges.PrintMemoryRegions();
    
    // Detections
    Analyze(j);

    // Print it
    PrintEvent(j);
    
    // Has to be at the end as we dont store reference
    json_entries.push_back(j);
    event_count++;

    return;
}


void Analyzer::ExtractMemoryInfo(nlohmann::json& j) {
    // Loaded dll's
    if (j["type"] == "loaded_dll") {
        for (const auto& it : j["dlls"]) {
            uint64_t addr = it["addr"].get<uint64_t>();
            uint64_t size = it["size"].get<uint64_t>();
            std::string protection = "???";
            std::string name = "loaded_dll:" + it["name"].get<std::string>();

            addr = AlignToPage(addr);
            // always add, as its early in the process without collisions hopefully
            MemoryRegion* region = new MemoryRegion(name, addr, size, protection);
            targetMemoryChanges.AddMemoryRegion(addr, region);
        }
    }

    // From injected dll
    if (j["type"] == "dll") {
        if (j["func"] == "AllocateVirtualMemory") {
            uint64_t addr = j["addr"].get<uint64_t>();
            uint64_t size = j["size"].get<uint64_t>();
            std::string protection = j["protect"];

            //std::string jsonString = j.dump();
            //std::cout << "Compact JSON: " << jsonString << std::endl;

            addr = AlignToPage(addr);
            MemoryRegion* memoryRegion = targetMemoryChanges.GetMemoryRegion(addr);
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
                targetMemoryChanges.AddMemoryRegion(addr, memoryRegion);
            }

            if (j["func"] == "FreeVirtualMemory") {
                uint64_t addr = j["addr"].get<uint64_t>();
                uint64_t size = j["size"].get<uint64_t>();

                MemoryRegion* memoryRegion = targetMemoryChanges.GetMemoryRegion(addr);
                if (memoryRegion != NULL) {
                    // do not remove, but indicate it has been freed
                    //targetMemoryChanges.RemoveMemoryRegion(addr, size);
                    memoryRegion->protection += ";freed";
                }
                else {
                    //LOG_A(LOG_WARNING, "Free a non-allocated");
                    // No add as its free anyway?
                }
            }
        }

        if (j["func"] == "ProtectVirtualMemory") {
            uint64_t addr = j["addr"].get<uint64_t>();
            uint64_t size = j["size"].get<uint64_t>();
            std::string protection = j["protect"];
            std::string name = "Protected";

            addr = AlignToPage(addr);
            // Check if exists
            MemoryRegion* memoryRegion = targetMemoryChanges.GetMemoryRegion(addr);
            if (memoryRegion == NULL) {
                //LOG_A(LOG_WARNING, "ProtectVirtualMemory region 0x%llx not found. Adding.",
                //    addr);
                MemoryRegion* region = new MemoryRegion(name, addr, size, protection);
                targetMemoryChanges.AddMemoryRegion(addr, region);
            }
            else {
                // Update protection
                MemoryRegion* region = targetMemoryChanges.GetMemoryRegion(addr);
                region->protection += ";" + protection;
                //LOG_A(LOG_INFO, "ProtectVirtualMemory: %s 0x%llx 0x%llx %s",
                //	name.c_str(), addr, size, protection.c_str());
            }
        }
    }
}


void Analyzer::Analyze(nlohmann::json& j) {
    BOOL printed = FALSE;

    if (j["type"] == "dll") {
        if (j["func"] == "AllocateVirtualMemory") {
            if (j["handle"] != -1) {
                std::stringstream ss;
                ss << "AllocateVirtualMemory in foreign process " << j["handle"].get<uint64_t>();
                AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
            }
        }
        if (j["func"] == "WriteVirtualMemory") {
            if (j["handle"] != -1) {
                std::stringstream ss;
                ss << "WriteVirtualMemory in foreign process " << j["handle"].get<uint64_t>();
                AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
            }
        }
        if (j["func"] == "CreateRemoteThread") {
            if (j["handle"] != -1) {
                std::stringstream ss;
                ss << "CreateRemoteThread in foreign process " << j["handle"].get<uint64_t>();
                AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
            }
        }
        if (j["func"] == "ProtectVirtualMemory") {
            // Check for simple RWX
            if (j.value("protect", "") == "RWX") {
                std::stringstream ss;
                ss << "Protect with RWX at addr " << j["addr"].get<uint64_t>();
                AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
            }

            // Check if the region has been suspiciously protected before (RW<->RX)
            uint64_t addr = j["addr"].get<uint64_t>();
            MemoryRegion* region = targetMemoryChanges.GetMemoryRegion(addr);
            if (region != NULL) {
                std::string sus = sus_protect(region->protection);
                if (sus != "") {
                    AnalyzerNewDetection(j, Criticality::HIGH, sus);
                }
            }
        }
        if (j["func"] == "MapViewOfSection") {
            // Check for simple RWX
            if (j.value("protect", "") == "RWX") {
                std::stringstream ss;
                ss << "Protect with RWX at addr " << j["addr"].get<uint64_t>();
                AnalyzerNewDetection(j, Criticality::HIGH, ss.str());
            }
        }

        // Check Injecte-DLL function callstack
        if (j.contains("callstack") && j["callstack"].is_array()) {
            for (const auto& callstack_entry : j["callstack"]) {
                // Callstack entry from RWX region
                if (callstack_entry["protect"] == "MEM_RWX") {
                    AnalyzerNewDetection(j, Criticality::HIGH, "RWX");
                }

                // Callstack entry from non-image region
                if (callstack_entry["type"] != "IMAGE") { // MEM_IMAGE
                    if (callstack_entry["type"] == "MAPPED") { // MEM_MAPPED
                        AnalyzerNewDetection(j, Criticality::LOW, "MEM_MAPPED");
                    }
                    else if (callstack_entry["type"] == "PRIVATE") { // MEM_PRIVATE, unbacked!
                        AnalyzerNewDetection(j, Criticality::HIGH, "MEM_PRIVATE");
                    }
                    else {
                        AnalyzerNewDetection(j, Criticality::MEDIUM, "MEM_UNKNOWN");
                    }
                }
            }
        }
    }
}


void Analyzer::AnalyzeEventStr(std::string eventStr) {
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
    GenerateNewTraceId();
    detections.clear();
    json_entries.clear();
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


void Analyzer::GenerateNewTraceId() {
	g_Analyzer.trace_id = rand();
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