#include <stdio.h>
#include <windows.h>
#include <cwchar>
#include <cstdlib>
#include <string>
#include <sstream>
#include <map>
#include <vector>
#include <wchar.h>
#include <stdio.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <iostream>

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
#include "utils.h"


BOOL EnableDebugPrivilege() {
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("OpenProcessToken failed. Error: %lu\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
		printf("LookupPrivilegeValue failed. Error: %lu\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
		printf("AdjustTokenPrivileges failed. Error: %lu\n", GetLastError());
		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	return TRUE;
}


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
	g_config.debug = true;
	printf("Get info about process: %lu\n", pid);
	g_config.hide_full_output = 0;
	g_config.targetExeName = L"Notepad";
	Process *p = g_ProcessCache.getObject(pid);

	printf("\n\nDisplay:\n");
	p->display();
}


void DoStuff() {
	constexpr unsigned char shellcode[] =
		"\xfc\x48";
	PBYTE       payload = (PBYTE)shellcode;
	SIZE_T      payloadSize = sizeof(shellcode);

	// RW
	PVOID shellcodeAddr = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (shellcodeAddr == NULL) {
		printf("VirtualAlloc failed\n");
		return;
	}

	// COPY
	memcpy(shellcodeAddr, payload, payloadSize);

	// RW->RWX
	DWORD dwOldProtection = NULL;
	if (!VirtualProtect(shellcodeAddr, payloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("VirtualProtect Failed With Error: %d \n", GetLastError());
		return;
	}

	// THREAD
	DWORD threadId;
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)shellcodeAddr, shellcodeAddr, 0, &threadId);
	if (hThread == NULL) {
		printf("CreateThread failed\n");
		return;
	}

	// WAIT
	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	return;
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
	for (auto& event : json_data) {
		g_Analyzer.AnalyzeEventJson(event);
	}

	g_Analyzer.targetInfo.PrintMemoryRegions();
}

#include "krabs.hpp"

void test() {

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
		EnableDebugPrivilege();
		InitProcessInfo();
		// Example: 1234 notepad.exe
		wchar_t* end;
		long pid = wcstoul(argv[2], &end, 10);
		Process process = Process();
		AugmentProcess(pid, &process);
	}
	else if (wcscmp(argv[1], L"analyzer") == 0) {
		if (argc == 3) {
			AnalyzeFile(argv[2]);
		}
		else {
			AnalyzeFile((wchar_t*) L"C:\\RedEdr\\Data\\notepad.events.txt");
		}
	}
	else if (wcscmp(argv[1], L"dostuff") == 0) {
		Sleep(500); // give time to do dll injection
		DoStuff();
	}
	else if (wcscmp(argv[1], L"test") == 0) {
		test();
	}
	else {
		LOG_A(LOG_ERROR, "Unknown command: %s", argv[1]);
	}
}
