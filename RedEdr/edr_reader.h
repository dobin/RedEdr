#pragma once

#include <string>


class EdrReader {
public:
	bool Start();
	bool Stop();

	std::string Get();

private:
	std::wstring GetISO8601Timestamp();
	std::string GetDefenderEventsSince(const std::wstring& isoTime);

	std::wstring start_time;
	std::string defender_eventlogs;
};

extern EdrReader g_EdrReader;
