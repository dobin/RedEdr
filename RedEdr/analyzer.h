#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <mutex>

#include "meminfo.h"


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


// Analyzer

class Analyzer {
public:
	Analyzer();
	void AnalyzeNewEvents(std::vector<std::string> events);
	void SaveToFile();
	std::string GetAllAsJson();

	std::string GetAllDetectionsAsJson();
	void ResetData();
	size_t GetDetectionsCount();

	// 
    std::vector<std::string> detections;
	TargetInfo targetMemoryChanges;

	int num_kernel = 0;
	int num_etw = 0;
	int num_etwti = 0;
	int num_dll = 0;

	void ExtractMemoryInfo(nlohmann::json& j);
	void PrintEvent(nlohmann::json j);
	void Analyze(nlohmann::json& j);
	void AnalyzeEventJson(nlohmann::json& j);
	void AnalyzeEventStr(std::string eventStr);
	void AnalyzerNewDetection(nlohmann::json& j, Criticality c, std::string s);

private:
	void GenerateNewTraceId();

	std::vector<nlohmann::json> json_entries;
	std::mutex output_mutex;
	size_t trace_id = 0;
	size_t event_count = 0;
};


DWORD WINAPI AnalyzerThread(LPVOID param);
int InitializeAnalyzer(std::vector<HANDLE>& threads);
void StopAnalyzer();

extern Analyzer g_Analyzer;
