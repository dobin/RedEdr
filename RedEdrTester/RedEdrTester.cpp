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

// Shared
#include "piping.h"
#include "utils.h"
#include "json.hpp"
#include "process_query.h"

// Stuff we test
#include "../RedEdr/config.h"
#include "../RedEdr/process_resolver.h"
#include "../RedEdr/event_processor.h"
#include "../RedEdr/mem_static.h"
#include "../RedEdr/dllinjector.h"
#include "../RedEdr/webserver.h"
#include "../RedEdr/kernelinterface.h"
#include "../RedEdr/serviceutils.h"


void SendToKernel(int enable, char* target) {
	printf("Sending: %d %s", enable, target);
	EnableKernelDriver(enable, target);
}


void SendToKernelReader(char* data) {
	PipeClient pipeClient;
	pipeClient.Connect(KERNEL_PIPE_NAME);
	pipeClient.Send(data);
	pipeClient.Disconnect();
}


void SendToDllReader(char* data) {
	PipeClient pipeClient;
	pipeClient.Connect(DLL_PIPE_NAME);
	pipeClient.Send(data);
	pipeClient.Disconnect();
}


void processinfo(char* pidStr) {
	PermissionMakeMeDebug();
	InitProcessQuery();

	long pid = strtol(pidStr, nullptr, 10);

	g_Config.debug = 1;
	g_Config.hide_full_output = 0;
	g_Config.targetExeName = "otepad";

	//Process* process = new Process(pid);
	Process* process = g_ProcessResolver.getObject(pid);  // use the real resolver
	
	// PEB
	ProcessPebInfoRet processPebInfoRet = ProcessPebInfo(process->GetHandle());
	printf("PEB:\n");
	printf("  Commandline: %s\n", processPebInfoRet.commandline.c_str());

	// DLLs
	std::vector<ProcessLoadedDll> processLoadedDlls = ProcessEnumerateModules(process->GetHandle());
	printf("\nLoaded DLLs (%llu):\n", processLoadedDlls.size());
	for (auto loadedDll : processLoadedDlls) {
		printf("0x%llx %lu %s\n", 
			loadedDll.dll_base,
			loadedDll.size,
			loadedDll.name.c_str());
	}

	// DLL sections
	printf("\nLoaded DLL regions:\n");
	for (auto processLoadedDll : processLoadedDlls) {
		std::vector<ModuleSection> moduleSections = EnumerateModuleSections(
			process->GetHandle(), uint64_to_pointer(processLoadedDll.dll_base));
		for (auto moduleSection : moduleSections) {
			printf("0x%llx %lu %s %s\n",
				moduleSection.addr,
				moduleSection.size,
				moduleSection.name.c_str(),
				moduleSection.protection.c_str());
		}
	}

	process->CloseTarget();
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


void AnalyzeFile(char *fname) {
	g_Config.hide_full_output = 1;
	g_Config.debug = 1;
	std::string filename = std::string(fname);
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
}




//#include "krabs.hpp"

void test() {

}

int main(int argc, char* argv[]) {
	if (argc < 1) {
		LOG_W(LOG_ERROR, L"Usage: %s <what>", argv[0]);
		return 1;
	}

	if (strcmp(argv[1], "send2kernel") == 0) {
		// Example: 1 notepad.exe
		long enable = strtol(argv[2], nullptr, 10);
		SendToKernel(enable, argv[3]);
	}
	else if (strcmp(argv[1], "send2kernelreader") == 0) {
		// Example: 
		SendToKernelReader(argv[2]);
	}
	else if (strcmp(argv[1], "send2dllreader") == 0) {
		// Example: 
		SendToDllReader(argv[2]);
	}
	else if (strcmp(argv[1], "processinfo") == 0) {
		processinfo(argv[2]);
	}
	else if (strcmp(argv[1], "analyzer") == 0) {
		if (argc == 3) {
			AnalyzeFile(argv[2]);
		}
		else {
			AnalyzeFile((char *) "C:\\RedEdr\\Data\\notepad.events.txt");
		}
	}
	else if (strcmp(argv[1], "dostuff") == 0) {
		Sleep(500); // give time to do dll injection
		DoStuff();
	}
	else if (strcmp(argv[1], "test") == 0) {
		test();
	}
	else {
		LOG_W(LOG_ERROR, L"Unknown command: %s", argv[1]);
	}
}
