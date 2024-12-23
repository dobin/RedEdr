#pragma once

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>


typedef void (WINAPI* EventRecordCallbackFuncPtr)(PEVENT_RECORD);

int InitializeEtwReader(std::vector<HANDLE>& threads);
void EtwReaderStopAll();
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType);
DWORD WINAPI TraceProcessingThread(LPVOID param);