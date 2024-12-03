#include <stdio.h>
#include <windows.h>
#include <cwchar>
#include <cstdlib>
#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <iostream>

#include <wchar.h>
#include <stdio.h>
#include <dbghelp.h>
#include <tlhelp32.h>

#include "../Shared/common.h"
#include "logging.h"
#include "config.h"

// Stuff we test
#include "processinfo.h"
#include "dllinjector.h"
#include "analyzer.h"
#include "webserver.h"
#include "processcache.h"
#include "analyzer.h"
#include "kernelinterface.h"
#include "piping.h"


void SendToKernel(int enable, wchar_t* target) {
	EnableKernelDriver(enable, target);
}

void SendToKernelReader(wchar_t* data) {
	PipeClient pipeClient;
	pipeClient.Connect(KERNEL_PIPE_NAME);
	pipeClient.Send(data);
	pipeClient.Disconnect();
}

void SendToDllReader(wchar_t* data) {
	PipeClient pipeClient;
	pipeClient.Connect(DLL_PIPE_NAME);
	pipeClient.Send(data);
	pipeClient.Disconnect();
}


void GetProcessInfo(DWORD pid, wchar_t* target) {
	printf("Get info about process: %lu\n", pid);
	g_config.hide_full_output = 0;
	g_config.targetExeName = L"Notepad";
	Process *p = g_ProcessCache.getObject(pid);
	p->display();
}


void AnalyzeFile(wchar_t *fname) {
	std::string filename = wcharToString(fname);
	LOG_A(LOG_INFO, "Analyzer: Reading %s", filename.c_str());
	std::string json_file_content = read_file(filename);
	if (json_file_content.empty()) {
		LOG_A(LOG_ERROR, "Could not read file");
		return; // Exit if the file could not be read
	}

	nlohmann::json json_data;
	try {
		json_data = nlohmann::json::parse(json_file_content);
	}
	catch (const std::exception& e) {
		std::cerr << "Failed to parse JSON: " << e.what() << std::endl;
		return;
	}
	if (!json_data.is_array()) {
		std::cerr << "JSON data is not an array." << std::endl;
		return;
	}
	for (const auto& event : json_data) {
		g_Analyzer.AnalyzeEventJson(event);
	}

	//g_Analyzer.targetInfo.PrintMemoryRegions();
}


int wmain(int argc, wchar_t* argv[]) {
	if (argc < 1) {
		LOG_A(LOG_ERROR, "Usage: %s <what> <data>", argv[0]);
		return 1;
	}

	if (wcscmp(argv[1], L"send2kernel") == 0) {
		// Example: 1 notepad.exe
		wchar_t* end;
		long enable = wcstol(argv[1], &end, 10);
		SendToKernel(enable, argv[2]);
	}
	else if (wcscmp(argv[1], L"send2kernelreader") == 0) {
		// Example: 
		SendToKernelReader(argv[2]);
	}
	else if (wcscmp(argv[1], L"send2dllreader") == 0) {
		// Example: 
		SendToDllReader(argv[2]);
	}
	else if (wcscmp(argv[1], L"processinfo") == 0) {
		// Example: 1234 notepad.exe
		wchar_t* end;
		long pid = wcstoul(argv[2], &end, 10);
		GetProcessInfo(pid, argv[3]);
	}
	else if (wcscmp(argv[1], L"analyzer") == 0) {
		AnalyzeFile(argv[2]);
	}
	else {
		LOG_A(LOG_ERROR, "Unknown command: %s", argv[1]);
	}
}
