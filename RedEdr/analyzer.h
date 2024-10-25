#include <windows.h>
#include <vector>

#include "json.hpp"

void AnalyzeEventJson(nlohmann::json j);
void AnalyzeEventStr(std::string eventStr);

DWORD WINAPI AnalyzerThread(LPVOID param);
int InitializeAnalyzer(std::vector<HANDLE>& threads);
void StopAnalyzer();
std::string GetAllDetectionsAsJson();
void AResetData();