

#include <iostream>
#include <sstream>
#include <vector>

#include <locale>
#include <codecvt>

#include "event_producer.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"
#include "analyzer.h"


HANDLE analyzer_thread;

enum class Criticality {
	LOW,
	MEDIUM,
	HIGH
};

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

std::string CriticalityToString(Criticality c) {
    switch (c) {
    case Criticality::LOW:   return "LOW";
    case Criticality::MEDIUM: return "MEDIUM";
    case Criticality::HIGH:  return "HIGH";
    default:          return "UNKNOWN";
    }
}

std::vector<std::string> detections;


void AResetData() {
	detections.clear();
}


std::string GetAllDetectionsAsJson() {
    nlohmann::json jsonArray = detections;
    return jsonArray.dump();
}

void AnalyzerNewDetection(Criticality c, std::string s) {
    std::string o = CriticalityToString(c) + ": " + s;
    LOG_A(LOG_WARNING, o.c_str());
    detections.push_back(o);
}

void PrintEvent(nlohmann::json j) {
	std::string output = j.dump();
	LOG_A(LOG_INFO, "Event: %s", output.c_str());
}


void AnalyzeEventJson(nlohmann::json j) {
    // Parse event
    BOOL printed = FALSE;

    //std::string protectStr = j["protect_str"].get<std::string>();
    //std::string callstackStr = j["callstack"].dump();

    // Allocate or map memory with RWX protection
    if (j["protect_str"] == "RWX") {
        j["detection"] += "RWX";
        Criticality c = Criticality::HIGH;

        std::stringstream ss;
        ss << "Analyzer: Function " << j["func"].get<std::string>() << " doing RWX";
        ss << " with size " << j["size"].get<std::string>();

        if (j["func"] == "MapViewOfSection") {
            ss << " SectionHandle " << j["section_handle"].get<std::string>();
            c = Criticality::LOW;
        }
        else if (j["func"] == "ProtectVirtualMemory") {
            //ss << " SectionHandle: " << j["section_handle"].get<std::string>();
            c = Criticality::HIGH;
        }
        AnalyzerNewDetection(c, ss.str());
        printed = TRUE;
    }

    int idx = 0;
    // Check callstack
    for (const auto& callstack_entry : j["callstack"]) {
        CriticalityManager cm;
        std::stringstream ss;
        BOOL print2 = FALSE;

        // Callstack entry from RWX region
        if (callstack_entry["protect"] == "0x40") {
            ss << "High: RWX section, ";
            j["detection"] += "RWX";
            cm.set(Criticality::HIGH);
            print2 = TRUE;
        } else if (callstack_entry["protect"] == "0x80") {
            ss << "Medium: RWX/C section, ";
            cm.set(Criticality::MEDIUM);
            print2 = TRUE;
        }

        // Callstack entry from non-image region
        if (callstack_entry["type"] != "0x1000000") { // MEM_IMAGE
            if (callstack_entry["type"] == "0x20000") { // MEM_MAPPED
                ss << "Low: MEM_MAPPED section, ";
                j["detection"] += "MEM_MAPPED";
                cm.set(Criticality::LOW);
                print2 = TRUE;
            }
            else if (callstack_entry["type"] == "0x40000") { // MEM_PRIVATE, unbacked!
                ss << "High: MEM_PRIVATE section, ";
                j["detection"] += "MEM_PRIVATE";
                cm.set(Criticality::HIGH);
                print2 = TRUE;
            }
            else if (callstack_entry["type"] == "0x0") { // MEM_INVALID
                ss << "Medium: MEM_INVALID (0x0) section, ";
                j["detection"] += "MEM_INVALID";
                cm.set(Criticality::MEDIUM);
                print2 = TRUE;
            }
            else {
                ss << "Unknown: MEM_UNKNOWN section, ";
                j["detection"] += "MEM_UNKNOWN";
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
            s << "Analyzer: Suspicious callstack " << idx << " of " << j["callstack"].size() << " by " << j["func"].get<std::string>();
            if (j["func"] == "ProtectVirtualMemory") {
				s << " destination " << j["base_addr"].get<std::string>();
                s << " protect " << j["protect_str"].get<std::string>();
			}
            s << " addr " << callstack_entry["addr"].get<std::string>();
            s << " protect " << callstack_entry["protect"].get<std::string>();
            s << " type " << callstack_entry["type"].get<std::string>();
            AnalyzerNewDetection(cm.get(), s.str());
        }
        idx += 1;
    }

}


void AnalyzeEventStr(std::string eventStr) {
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

DWORD WINAPI AnalyzerThread(LPVOID param) {
    LOG_A(LOG_INFO, "!Analyzer: Start thread");
    size_t arrlen = 0;
    std::unique_lock<std::mutex> lock(g_EventProducer.analyzer_shutdown_mtx);

    while (true) {
        // Block for new events
        g_EventProducer.cv.wait(lock, [] { return g_EventProducer.HasMoreEvents() || g_EventProducer.done; });

        // get em events
        std::vector<std::string> output_entries = g_EventProducer.GetEventsFrom();

        // handle em
        arrlen = output_entries.size();
        for (std::string& entry : output_entries) {
            AnalyzeEventStr(entry);
        }
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
    }
}
