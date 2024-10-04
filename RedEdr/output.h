#pragma once

#include <Windows.h>
#include <vector>

std::wstring ConvertLineToJson(const std::wstring& input);
void do_output(std::wstring str);
void print_all_output();
std::string GetJsonFromEntries();
int InitializeWebServer(std::vector<HANDLE>& threads);
void StopWebServer();