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
	std::string targetExeName = "powershell.exe";
	bool debug = false;

	// Constants
	LPCWSTR driverName = L"RedEdr";
	LPCWSTR driverPath = L"C:\\RedEdr\\RedEdrDriver\\RedEdrDriver.sys";
	LPCSTR inject_dll_path = "C:\\RedEdr\\RedEdrDll.dll";

	// Options
	bool hide_full_output = false;
	bool web_output = false;
	bool log_unload = false;
	bool do_udllinjection = false;
	bool debug_dllreader = false;
	bool enable_remote_exec = true;

	// Input selection
	bool do_etw = false;
	bool do_etwti = false;
	bool do_hook = false;
	bool do_dllinjection_ucallstack = true;

	// ETW input selection
	bool etw_standard = true;
	bool etw_kernelaudit = true;
	bool etw_secaudit = true;
	bool etw_defender = false;
};

extern Config g_Config;
