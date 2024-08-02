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
	const TCHAR* targetExeName = _T("notepad.exe");
	BOOL log_unload = FALSE;
};

extern Config g_config;
