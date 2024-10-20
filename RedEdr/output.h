#pragma once

#include <Windows.h>
#include <vector>


int InitializeAnalyzer(std::vector<HANDLE>& threads);
void StopAnalyzer();
void AnalyzeEvent(std::string eventStr);

int InitializeWebServer(std::vector<HANDLE>& threads);
void StopWebServer();
