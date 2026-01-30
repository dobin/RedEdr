#pragma once
#include <windows.h>
#include <vector>
#include <string>


class Config {
public:
	std::vector<std::string> targetProcessNames = {"malware"};
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
	
	// More input
	bool do_defendertrace = false;
	bool do_antimalwareengine = false;
	bool do_dllinjection_ucallstack = true;

	// ETW input selection
	bool etw_standard = true;
	bool etw_kernelaudit = true;
	bool etw_secaudit = true;
	bool etw_defender = false;
};

extern Config g_Config;
