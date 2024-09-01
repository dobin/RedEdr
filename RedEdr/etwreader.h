#pragma once

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

struct Reader {
    int id;
    wchar_t* SessionName;
    TRACEHANDLE SessionHandle;
    TRACEHANDLE TraceHandle;
};

extern Reader Readers[];



typedef void (WINAPI* EventRecordCallbackFuncPtr)(PEVENT_RECORD);

int InitializeEtwReader(std::vector<HANDLE>& threads);
Reader* setup_trace(int id, const wchar_t* guid, EventRecordCallbackFuncPtr func, const wchar_t* info);
Reader* setup_trace_security_auditing(int id);


// Helper
EVENT_TRACE_PROPERTIES* make_SessionProperties(int session_name_len);
void EnableProvider(TRACEHANDLE sessionHandle, const GUID& providerGuid);
void EtwReaderStopAll();
BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType);
DWORD WINAPI TraceProcessingThread(LPVOID param);