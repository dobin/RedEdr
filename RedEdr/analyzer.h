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

void AnalyzeEvent(std::string eventStr);
DWORD WINAPI AnalyzerThread(LPVOID param);
int InitializeAnalyzer(std::vector<HANDLE>& threads);
void StopAnalyzer();
std::string GetAllDetectionsAsJson();