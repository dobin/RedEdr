#pragma once

#include <Windows.h>
#include <vector>


int InitializeAnalyzer(std::vector<HANDLE>& threads);
void StopAnalyzer();

int InitializeWebServer(std::vector<HANDLE>& threads);
void StopWebServer();
