#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <mutex>

#include "json.hpp"
#include "myprocess.h"


class EventProcessor {
public:
	EventProcessor();
	void init();
	void InitialProcessInfo(Process* process);
	void AnalyzeNewEvents(std::vector<std::string> events);
	void SaveToFile();
	std::string GetAllAsJson();
	void ResetData();
	void EventStats(nlohmann::json& j);

	int num_kernel = 0;
	int num_etw = 0;
	int num_etwti = 0;
	int num_dll = 0;

	void PrintEvent(nlohmann::json j);
	void AnalyzeEventJson(nlohmann::json& j);
	void AnalyzeEventStr(std::string eventStr);

private:
	void GenerateNewTraceId();

	std::vector<nlohmann::json> json_entries;
	std::mutex output_mutex;
	size_t trace_id = 0;
	size_t event_count = 0;
};


DWORD WINAPI EventProcessorThread(LPVOID param);
int InitializeEventProcessor(std::vector<HANDLE>& threads);
void StopEventProcessor();

extern EventProcessor g_EventProcessor;
