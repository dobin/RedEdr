#pragma once

#include <windows.h>
#include <evntrace.h>
#include <vector>


typedef void (WINAPI* EventRecordCallbackFuncPtr)(PEVENT_RECORD);

int InitializeEtwReader(std::vector<HANDLE>& threads);
void EtwReaderStopAll();
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType);
DWORD WINAPI TraceProcessingThread(LPVOID param);
void enable_additional_etw(BOOL use);