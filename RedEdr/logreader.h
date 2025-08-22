#pragma once

#include <windows.h>
#include <vector>
#include <string>


std::wstring findFiles(const std::wstring& directory, const std::wstring& pattern);
BOOL InitializeLogReader(std::vector<HANDLE>& threads);
void tailFileW(const wchar_t* filePath);
void LogReaderStopAll();