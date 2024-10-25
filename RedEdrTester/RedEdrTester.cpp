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
#include "helper.h"


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
	Process* process = MakeProcess(pid, target);
	process->display();
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
		long pid = wcstoul(argv[1], &end, 10);
		GetProcessInfo(pid, argv[3]);
	}
	else {
		LOG_A(LOG_ERROR, "Unknown command: %s", argv[1]);
	}
}
