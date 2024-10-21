

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

std::vector<std::string> detections;

std::string GetAllDetectionsAsJson() {
    nlohmann::json jsonArray = detections;
    return jsonArray.dump();
}

void AnalyzerNewDetection(const char *s) {
    LOG_A(LOG_WARNING, s);
    detections.push_back(std::string(s));
}


void AnalyzeEvent(std::string eventStr) {
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

    // Parse event
    //std::string protectStr = j["protect_str"].get<std::string>();
    //std::string callstackStr = j["callstack"].dump();

    if (j["protect_str"] == "RWX") {
        AnalyzerNewDetection("Analyzer: RWX detected");
    }

    for (const auto& callstack_entry : j["callstack"]) {
        if (callstack_entry["protect"] == "0x40" || callstack_entry["protect"] == "0x40") {
            AnalyzerNewDetection("Analyzer: Suspicious callstack detected: RWX");
        }

        if (callstack_entry["type"] != "0x1000000") {
            AnalyzerNewDetection("Analyzer: Suspicious callstack detected: Non-image");
        }
    }
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
            AnalyzeEvent(entry);
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
