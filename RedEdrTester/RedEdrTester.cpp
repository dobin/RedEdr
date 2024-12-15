/*
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
*/

#include <iostream>

#include <krabs.hpp>

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
	//EnableKernelDriver(enable, target);
}

void SendToKernelReader(wchar_t* data) {
	/*PipeClient pipeClient;
	pipeClient.Connect(KERNEL_PIPE_NAME);
	pipeClient.Send(data);
	pipeClient.Disconnect();
*/
}

void SendToDllReader(wchar_t* data) {
	/*PipeClient pipeClient;
	pipeClient.Connect(DLL_PIPE_NAME);
	pipeClient.Send(data);
	pipeClient.Disconnect();*/
}


void GetProcessInfo(DWORD pid, wchar_t* target) {
	/*
	printf("Get info about process: %lu\n", pid);
	g_config.hide_full_output = 0;
	g_config.targetExeName = L"Notepad";
	Process *p = g_ProcessCache.getObject(pid);
	p->display();
	*/
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
	/*
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

	//g_Analyzer.targetInfo.PrintMemoryRegions();
	*/
}


void Bluekrabs()
{
	/*
	thread_dispatch_provider
	dpc_provider
	image_load_provider
	process_provider
	system_call_provider
	thread_provider
	vamap_provider
	virtual_alloc_provider
	*/

	krabs::kernel_trace trace(L"My magic trace");
	krabs::kernel::thread_dispatch_provider thread_dispatch_provider;
	krabs::kernel::image_load_provider image_load_provider;
	krabs::kernel::dpc_provider dpc_provider;
	krabs::kernel::process_provider process_provider;
	krabs::kernel::system_call_provider system_call_provider;
	krabs::kernel::thread_provider thread_provider;
	krabs::kernel::vamap_provider vamap_provider;
	krabs::kernel::virtual_alloc_provider virtual_alloc_provider;

	image_load_provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
		krabs::schema schema(record, trace_context.schema_locator);
		krabs::parser parser(schema);

		std::wcout << std::to_wstring(record.EventHeader.ProviderId);
		std::wcout << L" provider=" << schema.provider_name();
		std::wcout << L" event_name=" << schema.event_name();
		std::wcout << L" task_name=" << schema.task_name();
		std::wcout << L" opcode=" << schema.event_opcode();
		std::wcout << L" opcode_name=" << schema.opcode_name();
		std::wcout << std::endl;

		for (const auto& property : parser.properties()) {
			try {
				// Get the name and type of the property
				const std::wstring& propertyName = property.name();
				const auto propertyType = property.type();


				// Parse the property value using the parser
				std::wcout << L"Property Name: " << propertyName << L", ";
				switch (propertyType) {
				case TDH_INTYPE_UINT32:
					std::wcout << L"Value: " << parser.parse<uint32_t>(propertyName) << L"\n";
					break;
				case TDH_INTYPE_UINT64:
					std::wcout << L"Value: " << parser.parse<uint64_t>(propertyName) << L"\n";
					break;
				case TDH_INTYPE_UNICODESTRING:
					std::wcout << L"Value: " << parser.parse<std::wstring>(propertyName) << L"\n";
					break;
				case TDH_INTYPE_ANSISTRING:
					std::cout << "Value: " << parser.parse<std::string>(propertyName) << "\n";
					break;
				default:
					std::wcout << L"Value: (Unsupported type)\n";
					break;
				}
			}
			catch (const std::exception& ex) {
				std::wcout << L"Failed to parse property: " << ex.what() << L"\n";
			}
		}
	});
	system_call_provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
		krabs::schema schema(record, trace_context.schema_locator);
		std::wcout << std::to_wstring(record.EventHeader.ProviderId);
		std::wcout << L" provider=" << schema.provider_name();
		std::wcout << L" event_name=" << schema.event_name();
		std::wcout << L" task_name=" << schema.task_name();
		std::wcout << L" opcode=" << schema.event_opcode();
		std::wcout << L" opcode_name=" << schema.opcode_name();
		std::wcout << std::endl;
	});

	trace.enable(image_load_provider);
	//trace.enable(system_call_provider);

	printf("Start\n");
	trace.start();
	trace.stop();
	printf("Stop\n");
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
		/*InitProcessInfo();
		// Example: 1234 notepad.exe
		wchar_t* end;
		long pid = wcstoul(argv[2], &end, 10);
		GetProcessInfo(pid, argv[3]);*/
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
	else if (wcscmp(argv[1], L"bluekrabs") == 0) {
		Bluekrabs();
	}
	else {
		LOG_A(LOG_ERROR, "Unknown command: %s", argv[1]);
	}
}
