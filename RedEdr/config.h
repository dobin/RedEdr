#pragma once
#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <tchar.h>

class Config {
public:
	LPCWSTR targetExeName = L"powershell.exe"; // = const LPWSTR
	BOOL log_unload = FALSE;
	std::wstring sessionName = L"ETWReader";
	WCHAR* a;
};

extern Config g_config;
