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

	LPCSTR inject_dll_path = "C:\\Users\\hacker\\source\\repos\\rededr\\x64\\Release\\SylantStrike.dll";
	bool do_etw = false;
	bool do_mplog = false;
	bool do_kernelcallback = false;
	bool do_dllinjection = false;
	//bool do_dllinjection_nochildren = false;
};

extern Config g_config;
