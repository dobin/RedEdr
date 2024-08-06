#pragma once

#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <tchar.h>
#include <vector>
#include <fstream>
#include <string>
#include <tdh.h>
#include <iomanip>
#include <sstream>


std::wstring findFiles(const std::wstring& directory, const std::wstring& pattern);
BOOL InitializeLogReader(std::vector<HANDLE>& threads);
void tailFileW(const wchar_t* filePath);
void LogReaderStopAll();