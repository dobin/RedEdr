#pragma once

#include <iostream>
#include <sstream>
#include <vector>
#include <mutex>


class EventProducer {
public:
	void do_output(std::wstring str);

	std::string ConvertLogLineToJsonEvent(const std::wstring& input);
	std::string GetAllAsJson();
	void PrintAll();
	void ResetData();

	// Only support one consumer, as it tracks its last used element
	BOOL HasMoreEvents();
	std::vector<std::string> GetEventsFrom();
	
	// These is all just so a consumer can get a copy of all new
	// events (Analyzer)
	std::condition_variable cv; // Will be called upon each insert
	std::mutex analyzer_shutdown_mtx;
	bool done = false;  // Flag to signal when to stop the consumer thread
	int last = -1;

private:
	// JSON should be UTF-8 which is std::string...
	std::vector<std::string> output_entries;
	std::mutex output_mutex;
	unsigned int output_count = 0;
};

extern EventProducer g_EventProducer;
