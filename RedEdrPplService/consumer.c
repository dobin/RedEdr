#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <combaseapi.h>

#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <evntrace.h>

#include "emitter.h"
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "tdh.lib")

/* NOTE: Copied from etwreader.cpp */

//wchar_t* SessionName = L"RedEdrPplServiceEtwTiReader_2";
wchar_t* SessionName = L"RedEdr__11";

BOOL enabled_consumer = FALSE;

void enable_consumer(BOOL e) {
    log_message(L"Consumer: Enable: %d", e);
    enabled_consumer = e;
}


void PrintProperties(wchar_t *eventName, PEVENT_RECORD eventRecord) {
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO eventInfo = NULL;
    TDHSTATUS status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        eventInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    }
    if (ERROR_SUCCESS != status) {
        wprintf(L"TdhGetEventInformation failed\n");
        if (eventInfo) {
            free(eventInfo);
        }
        return;
    }

    wchar_t output [1024] = { 0 }; // Buffer to accumulate output
    swprintf(output, sizeof(output) / sizeof(output[0]),
        L"type:etw;time:%lld;pid:%lu;thread_id:%lu;event:%s;",
        eventRecord->EventHeader.TimeStamp.QuadPart,
        eventRecord->EventHeader.ProcessId,
        eventRecord->EventHeader.ThreadId,
        eventName);

    if (eventInfo->ProviderNameOffset) {
        wcscat_s(output, sizeof(output) / sizeof(output[0]), (wchar_t*)((PBYTE)eventInfo + eventInfo->ProviderNameOffset));
    }
    else {
        wcscat_s(output, sizeof(output) / sizeof(output[0]), L"Unknown");
    }
    wcscat_s(output, sizeof(output) / sizeof(output[0]), L";");

    for (DWORD i = 0; i < eventInfo->TopLevelPropertyCount; i++) {
        PROPERTY_DATA_DESCRIPTOR dataDescriptor;
        dataDescriptor.PropertyName = (ULONGLONG)((PBYTE)eventInfo + eventInfo->EventPropertyInfoArray[i].NameOffset);
        dataDescriptor.ArrayIndex = ULONG_MAX;

        bufferSize = 0;
        status = TdhGetPropertySize(eventRecord, 0, NULL, 1, &dataDescriptor, &bufferSize);
        if (status != ERROR_SUCCESS) {
            continue;
        }

        BYTE* propertyBuffer = (BYTE*)malloc(bufferSize);
        status = TdhGetProperty(eventRecord, 0, NULL, 1, &dataDescriptor, bufferSize, propertyBuffer);
        if (status != ERROR_SUCCESS) {
            free(propertyBuffer);
            continue;
        }

        wcscat_s(output, sizeof(output) / sizeof(output[0]), (wchar_t*)((PBYTE)eventInfo + eventInfo->EventPropertyInfoArray[i].NameOffset));
        wcscat_s(output, sizeof(output) / sizeof(output[0]), L":");

        switch (eventInfo->EventPropertyInfoArray[i].nonStructType.InType) {
        case TDH_INTYPE_UINT32:
            swprintf(output + wcslen(output), 32, L"%lu;", *(PULONG)propertyBuffer);
            break;
        case TDH_INTYPE_UINT64:
            swprintf(output + wcslen(output), 32, L"%llu;", *(PULONG64)propertyBuffer);
            break;
        case TDH_INTYPE_UNICODESTRING:
            wcscat_s(output, sizeof(output) / sizeof(output[0]), (PCWSTR)propertyBuffer);
            wcscat_s(output, sizeof(output) / sizeof(output[0]), L";");
            break;
        case TDH_INTYPE_ANSISTRING: {
            size_t convertedChars = 0;
            wchar_t convertedString[256];
            mbstowcs_s(&convertedChars, convertedString, sizeof(convertedString) / sizeof(convertedString[0]), (PCSTR)propertyBuffer, bufferSize);
            wcscat_s(output, sizeof(output) / sizeof(output[0]), convertedString);
            wcscat_s(output, sizeof(output) / sizeof(output[0]), L";");
            break;
        }
        case TDH_INTYPE_POINTER:
            swprintf(output + wcslen(output), 32, L"0x%p;", *(PVOID*)propertyBuffer);
            break;
        case TDH_INTYPE_FILETIME: {
            FILETIME fileTime = *(PFILETIME)propertyBuffer;
            SYSTEMTIME stUTC, stLocal;
            FileTimeToSystemTime(&fileTime, &stUTC);
            SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
            swprintf(output + wcslen(output), 64, L"%04d/%02d/%02d %02d:%02d:%02d;",
                stLocal.wYear, stLocal.wMonth, stLocal.wDay,
                stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
            break;
        }
        default:
            wcscat_s(output, sizeof(output) / sizeof(output[0]), L"(Unknown type);");
            break;
        }

        free(propertyBuffer);
    }

    if (eventInfo) {
        free(eventInfo);
    }

    // Output the accumulated string
    //wprintf(L"%s\n", output);

    SendEmitterPipe(output);
}

void WINAPI EventRecordCallbackKernelProcess(PEVENT_RECORD eventRecord) {
    if (eventRecord == NULL || !enabled_consumer) {
        return;
    }
    wchar_t id[32];

    // Do we want to track this process?
    //DWORD processId = eventRecord->EventHeader.ProcessId;
    //if (!g_cache.observe(processId)) {
    //    return;
    //}

    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 1:
        //log_message(L"-> Start process");
        //SendEmitterPipe(L"-> Sart Process: enabled: %d", enabled_consumer);
        wcsncpy_s(id, 32, L"StartProcess", _TRUNCATE);
        break;
    case 3:
        //log_message(L"-> Start thread");
        //SendEmitterPipe(L"-> Sart thread");
        wcsncpy_s(id, 32, L"StartThread", _TRUNCATE);
        break;
    case 5:
        wcsncpy_s(id, 32, L"LoadImage", _TRUNCATE);
        //log_message(L"-> load image");
        break;
    default:
        return;
    }

    PrintProperties(id, eventRecord);
}



void WINAPI EventRecordCallbackTi(PEVENT_RECORD eventRecord) {
    if (eventRecord == NULL || !enabled_consumer) {
        return;
    }

    wchar_t buffer[32] = { 0 };
    swprintf_s(buffer, sizeof(buffer) / sizeof(buffer[0]), L"<%d>", eventRecord->EventHeader.EventDescriptor.Id);
    PrintProperties(buffer, eventRecord);

    // Do we want to track this process?
    //DWORD processId = eventRecord->EventHeader.ProcessId;
    //if (!g_cache.observe(processId)) {
    //    return;
    //}
    /*
    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 1:
        //log_message(L"-> Start process");
        SendEmitterPipe(L"-> Sart Process: enabled2: %d", enabled_consumer);
        break;
    case 3:
        //log_message(L"-> Start thread");
        //SendEmitterPipe(L"-> Sart thread");
        break;
    case 5:
        //log_message(L"-> load image");
        break;
    }
    */

    //PrintProperties(eventName, eventRecord);
}


DWORD WINAPI TraceProcessingThread(LPVOID param) {
    setup_trace(L"{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}", &EventRecordCallbackTi, L"Microsoft-Windows-Threat-Intelligence");
    //setup_trace(L"{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}", &EventRecordCallbackKernelProcess, L"Microsoft-Windows-Kernel-Process");
    return 0;
}


void initialize_etwti_reader() {
    TraceProcessingThread(NULL);
}


typedef void (WINAPI* EventRecordCallbackFuncPtr)(PEVENT_RECORD);

TRACEHANDLE SessionHandle;
TRACEHANDLE TraceHandle;


EVENT_TRACE_PROPERTIES* make_SessionProperties(size_t session_name_len) {
    EVENT_TRACE_PROPERTIES* sessionProperties;
    ULONG bufferSize = (ULONG)(sizeof(EVENT_TRACE_PROPERTIES) + ((session_name_len + 1) * sizeof(wchar_t)));
    sessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (sessionProperties == NULL) {
        log_message(L"Allocating");
        return NULL;
    }
    ZeroMemory(sessionProperties, bufferSize);
    sessionProperties->Wnode.BufferSize = bufferSize;
    sessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    sessionProperties->Wnode.ClientContext = 1;  // QPC clock resolution
    sessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    return sessionProperties;
}


BOOL shutdown_etwti_reader() {
    log_message(L"--[ Stopping EtwTracing");
    ULONG status;
    EVENT_TRACE_PROPERTIES* sessionProperties;

    sessionProperties = make_SessionProperties(wcslen(SessionName));
    if (SessionHandle != NULL) {
        log_message(L"  Stop Session with ControlTrace(EVENT_TRACE_CONTROL_STOP)");
        status = ControlTrace(SessionHandle, SessionName, sessionProperties, EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS) {
            log_message(L"    Failed to stop trace");
        }
        else {
            log_message(L"    ControlTrace stopped");
        }
        SessionHandle = NULL;
    }
    free(sessionProperties);

    if (TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        log_message(L"  CloseTrace()");

        status = CloseTrace(TraceHandle);
        if (status == ERROR_CTX_CLOSE_PENDING) {
            // The call was successful. The ProcessTrace function will stop 
            // after it has processed all real-time events in its buffers 
            // (it will not receive any new events).
            log_message(L"    CloseTrace() success but pending");
        }
        else if (status == ERROR_SUCCESS) {
            log_message(L"    CloseTrace() success");
        }
        else {
            log_message(L"    CloseTrace() failed: %d", status);
        }
        TraceHandle = INVALID_PROCESSTRACE_HANDLE;
    }
}


BOOL setup_trace(const wchar_t* guid, EventRecordCallbackFuncPtr func, const wchar_t* info) {
    ULONG status;
    GUID providerGuid;
    SessionHandle = NULL;
    TraceHandle = INVALID_PROCESSTRACE_HANDLE;

    log_message(L"--[ Setup ETW-TI Reader");

    // Convert CLSID
    if (CLSIDFromString(guid, &providerGuid) != NOERROR) {
        log_message(L"Invalid provider GUID format");
        return FALSE;
    }

    // StartTrace -> SessionHandle
    EVENT_TRACE_PROPERTIES* sessionProperties = make_SessionProperties(wcslen(SessionName));
    status = StartTrace(&SessionHandle, SessionName, sessionProperties);
    if (status != ERROR_SUCCESS) {
        log_message(L"Failed to start trace: %d", status);
        free(sessionProperties);

        if (status == ERROR_ALREADY_EXISTS) {
            log_message(L"-> Already exists");
        }

        return FALSE;
    }

    // EnableProvider
    status = EnableTraceEx2(SessionHandle,  &providerGuid, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION, 0, 0, 0, NULL);
    if (status != ERROR_SUCCESS) {
        log_message(L"Failed to enable provider: %d", status);
        if (status == ERROR_ACCESS_DENIED) {
            log_message(L"No permission, start in elevated prompt");
        }
        return FALSE;
    }

    // OpenTrace
    EVENT_TRACE_LOGFILE traceLogfile;
    ZeroMemory(&traceLogfile, sizeof(EVENT_TRACE_LOGFILE));
    traceLogfile.LoggerName = SessionName;
    traceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLogfile.EventRecordCallback = func;
    TraceHandle = OpenTrace(&traceLogfile);
    if (TraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        log_message(L"Failed to open trace: %d", GetLastError());
        free(sessionProperties);
        return NULL;
    }
    free(sessionProperties);

    // Start it (blocking)
    TRACEHANDLE traceHandles[] = { TraceHandle };
    log_message(L"--[ ETW Listening now...");
    status = ProcessTrace(traceHandles, 1, 0, 0);
    if (status != ERROR_SUCCESS) {
        log_message(L"ProcessTrace() failed with error: %d", status);
    }

    log_message(L"--[ All good");
}


