#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <sddl.h>

#include "logging.h"
#include "etwconsumer.h"
#include "utils.h"


#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")


// EtwConsumer: Interact with ETW


// Local functions
EVENT_TRACE_PROPERTIES* MakeSessionProperties(size_t session_name_len);


EtwConsumer::EtwConsumer() {
	id = -1;
	SessionName = NULL;
	SessionHandle = NULL;
	TraceHandle = INVALID_PROCESSTRACE_HANDLE;
}


BOOL EtwConsumer::SetupEtw(int _id, const wchar_t* guid, 
	EventRecordCallbackFuncPtr func, const wchar_t* info, 
    const wchar_t* sessionName) {

    ULONG status;
    GUID providerGuid;
    TRACEHANDLE sessionHandle;
    TRACEHANDLE traceHandle;
    id = _id;
    LOG_A(LOG_INFO, "ETW: Do Trace %i: %ls: %ls", id, guid, info);
    
    // For session name omg...
    std::wstring mySessionName = std::wstring(sessionName) + L"_" + std::to_wstring(id);
    SessionName = wstring2wchar(mySessionName);

    // Initialize handles (assuming INVALID_PROCESSTRACE_HANDLE and NULL are valid initial values)
    SessionHandle = NULL;
    TraceHandle = INVALID_PROCESSTRACE_HANDLE;

    if (CLSIDFromString(guid, &providerGuid) != NOERROR) {
        LOG_A(LOG_ERROR, "ETW: Invalid provider GUID format");
        return FALSE;
    }

    // StartTrace -> SessionHandle
    EVENT_TRACE_PROPERTIES* sessionProperties = MakeSessionProperties(wcslen(SessionName));
    status = StartTrace(&sessionHandle, SessionName, sessionProperties);
    if (status == ERROR_ALREADY_EXISTS) {
        LOG_A(LOG_WARNING, "ETW: Session %ls already exists, attempt to stop it", mySessionName.c_str());
        StopEtw();
        Sleep(500);

        // Try it again...
        LOG_A(LOG_WARNING, "ETW: Attempt to open trace %ls again..", mySessionName.c_str());
        status = StartTrace(&sessionHandle, SessionName, sessionProperties);
        if (status != ERROR_SUCCESS) {
            LOG_A(LOG_WARNING, "ETW: Failed to open session %ls", mySessionName.c_str());
            free(sessionProperties);
            return FALSE;
        }
    }
    else if (status != ERROR_SUCCESS) {
        LOG_A(LOG_ERROR, "ETW: Failed to start trace: %d", status);
        free(sessionProperties);
        return FALSE;
    }

    LOG_A(LOG_WARNING, "ETW: StartTrace %ls success", mySessionName.c_str());

    // EnableProvider
    status = EnableTraceEx2(
        sessionHandle,
        &providerGuid,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_INFORMATION,
        0,
        0,
        0,
        NULL
    );
    if (status != ERROR_SUCCESS) {
        LOG_A(LOG_ERROR, "ETW: Failed to enable provider: %d", status);
    }

    // OpenTrace
    EVENT_TRACE_LOGFILE traceLogfile;
    ZeroMemory(&traceLogfile, sizeof(EVENT_TRACE_LOGFILE));
    traceLogfile.LoggerName = SessionName;
    traceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLogfile.EventRecordCallback = func;
    traceHandle = OpenTrace(&traceLogfile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        LOG_A(LOG_ERROR, "ETW: Failed to open trace: %d", GetLastError());
        free(sessionProperties);
        return FALSE;
    }

    SessionHandle = sessionHandle;
    TraceHandle = traceHandle;

    free(sessionProperties);

    return TRUE;
}


BOOL EtwConsumer::SetupEtwSecurityAuditing(int _id, EventRecordCallbackFuncPtr func, const wchar_t* sessionName)
{
    // Microsoft-Windows-Security-Auditing is different
    // https://github.com/microsoft/krabsetw/blob/e39e9b766a2b77a5266f0ab4b776e0ca367b3409/examples/NativeExamples/user_trace_005.cpp#L4
    // https://github.com/microsoft/krabsetw/issues/79
    // https://github.com/microsoft/krabsetw/issues/5

    const wchar_t *guid = L"{54849625-5478-4994-A5BA-3E3B0328C30D}";
    const wchar_t *info = L"Microsoft-Windows-Security-Auditing";

    id = _id;

    // For session name omg...
    std::wstring mySessionName = std::wstring(sessionName) + L"_" + std::to_wstring(id);
    SessionName = wstring2wchar(mySessionName);

    // Initialize handles (assuming INVALID_PROCESSTRACE_HANDLE and NULL are valid initial values)
    SessionHandle = NULL;
    TraceHandle = INVALID_PROCESSTRACE_HANDLE;

    LOG_A(LOG_INFO, "ETW: Do Trace %i: %ls: %ls", id, guid, info);

    // Only one trace session is allowed for this provider: "EventLog-Security"
    // Open a handle to this trace session
    EVENT_TRACE_LOGFILE trace;
    ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
    trace.LoggerName = const_cast<LPWSTR>(L"EventLog-Security");
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(func);

    // Open trace
    TRACEHANDLE traceHandle = OpenTrace(&trace);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        LOG_A(LOG_ERROR, "ETW: Failed to open trace. Error: %d", GetLastError());
        return FALSE;
    }

    DWORD x = ERROR_CTX_CLOSE_PENDING;
    SessionHandle = NULL;  // Dont have no session
    TraceHandle = traceHandle;

    return TRUE;
}


// Blocking
//   calls the callback
BOOL EtwConsumer::StartEtw() {
    TRACEHANDLE traceHandles[] = { TraceHandle };
    ULONG status = ProcessTrace(traceHandles, 1, NULL, NULL);
    if (status != ERROR_SUCCESS) {
        LOG_A(LOG_ERROR, "ETW: Failed to process trace: %d", status);
        return FALSE;
    }
    return TRUE;
}


void EtwConsumer::StopEtw() {
    /* Note:
        The ProcessTrace function blocks the thread until
          it delivers all events,
          the BufferCallback function returns FALSE,
          or you call CloseTrace.
        In addition, if the consumer is consuming events in real time, the ProcessTrace
        function returns after the controller stops the trace session.
        (Note that there may be a delay of several seconds before the function returns.)
    */
    ULONG status;
    EVENT_TRACE_PROPERTIES* sessionProperties;
    sessionProperties = MakeSessionProperties(wcslen(SessionName));

    LOG_A(LOG_INFO, "ETW:  Stop Session: %ls", SessionName);
    if (SessionHandle != NULL) {
        status = ControlTrace(SessionHandle, SessionName, sessionProperties, EVENT_TRACE_CONTROL_STOP);
        if (status != ERROR_SUCCESS) {
            LOG_A(LOG_WARNING, "ETW:     Failed to stop trace, error: %d", status);
        }
        else {
            LOG_A(LOG_INFO, "ETW:     ControlTrace stopped");
        }
        free(sessionProperties);
    }

    if (TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        LOG_A(LOG_INFO, "ETW:   CloseTrace(): %i", id);

        status = CloseTrace(TraceHandle);
        if (status == ERROR_CTX_CLOSE_PENDING) {
            // The call was successful. The ProcessTrace function will stop 
            // after it has processed all real-time events in its buffers 
            // (it will not receive any new events).
            LOG_A(LOG_INFO, "ETW:     CloseTrace() success but pending");
        }
        else if (status == ERROR_SUCCESS) {
            LOG_A(LOG_INFO, "ETW:     CloseTrace() success");
        }
        else {
            LOG_A(LOG_WARNING, "ETW:     CloseTrace() failed: %d", status);
        }
        TraceHandle = INVALID_PROCESSTRACE_HANDLE;
    }
}


int EtwConsumer::getId() {
    return id;
}


/** Helpers **/

std::wstring EtwEventToStr(std::wstring eventName, PEVENT_RECORD eventRecord) {
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO eventInfo = NULL;
    TDHSTATUS status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        eventInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    }
    if (ERROR_SUCCESS != status) {
        LOG_A(LOG_ERROR, "TdhGetEventInformation");
        if (eventInfo) {
            free(eventInfo);
        }
        return std::wstring(L"");
    }

    // String stream to accumulate output
    std::wstringstream output;
    output << L"type:etw;time:" << static_cast<__int64>(eventRecord->EventHeader.TimeStamp.QuadPart) << L";";
    output << L"pid:" << eventRecord->EventHeader.ProcessId << L";";
    output << L"thread_id:" << eventRecord->EventHeader.ThreadId << L";";
    output << L"event:" << eventName << L";";

    //output << L"EventID:" << eventRecord->EventHeader.EventDescriptor.Id << L";";
    output << L"provider_name:" << (eventInfo->ProviderNameOffset ? (PCWSTR)((PBYTE)eventInfo + eventInfo->ProviderNameOffset) : L"Unknown") << L";";

    for (DWORD i = 0; i < eventInfo->TopLevelPropertyCount; i++) {
        PROPERTY_DATA_DESCRIPTOR dataDescriptor;
        dataDescriptor.PropertyName = (ULONGLONG)((PBYTE)eventInfo + eventInfo->EventPropertyInfoArray[i].NameOffset);
        dataDescriptor.ArrayIndex = ULONG_MAX;

        bufferSize = 0;
        status = TdhGetPropertySize(eventRecord, 0, NULL, 1, &dataDescriptor, &bufferSize);
        if (status != ERROR_SUCCESS) {
            continue;
        }

        std::vector<BYTE> propertyBuffer(bufferSize);
        status = TdhGetProperty(eventRecord, 0, NULL, 1, &dataDescriptor, bufferSize, propertyBuffer.data());
        if (status != ERROR_SUCCESS) {
            continue;
        }

        output << reinterpret_cast<PCWSTR>((PBYTE)eventInfo + eventInfo->EventPropertyInfoArray[i].NameOffset) << L":";

        switch (eventInfo->EventPropertyInfoArray[i].nonStructType.InType) {
        case TDH_INTYPE_UINT32:
            output << *reinterpret_cast<PULONG>(propertyBuffer.data()) << L";";
            break;
        case TDH_INTYPE_UINT64:
            output << *reinterpret_cast<PULONG64>(propertyBuffer.data()) << L";";
            break;
        case TDH_INTYPE_UNICODESTRING:
            output << reinterpret_cast<PCWSTR>(propertyBuffer.data()) << L";";
            break;
        case TDH_INTYPE_ANSISTRING:
            output << reinterpret_cast<PCSTR>(propertyBuffer.data()) << L";";
            break;
        case TDH_INTYPE_POINTER:  // hex
            output << L"0x" << reinterpret_cast<PVOID>(propertyBuffer.data()) << L";";
            break;
        case TDH_INTYPE_FILETIME:
        {
            FILETIME fileTime = *reinterpret_cast<PFILETIME>(propertyBuffer.data());
            SYSTEMTIME stUTC, stLocal;
            FileTimeToSystemTime(&fileTime, &stUTC);
            SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
            output << stLocal.wYear << L"/" << stLocal.wMonth << L"/" << stLocal.wDay << L" "
                << stLocal.wHour << L"." << stLocal.wMinute << L"." << stLocal.wSecond << L";";
            break;
        }
        default:
            output << L"(Unknown type);";
            break;
        }
    }

    // Free the event information structure
    if (eventInfo) {
        free(eventInfo);
    }

    return output.str();
}


void PrintProperties_2(wchar_t* eventName, PEVENT_RECORD eventRecord) {
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO eventInfo = NULL;
    TDHSTATUS status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        eventInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    }
    if (ERROR_SUCCESS != status) {
        LOG_W(LOG_INFO, L"Consumer: TdhGetEventInformation failed\n");
        if (eventInfo) {
            free(eventInfo);
        }
        return;
    }

    wchar_t output[1024] = { 0 }; // Buffer to accumulate output
    swprintf(output, sizeof(output) / sizeof(output[0]),
        L"type:etw;time:%lld;pid:%lu;thread_id:%lu;event:%s;provider_name:Microsoft-Windows-Threat-Intelligence;",
        eventRecord->EventHeader.TimeStamp.QuadPart,
        eventRecord->EventHeader.ProcessId,
        eventRecord->EventHeader.ThreadId,
        eventName);

    /*if (eventInfo->ProviderNameOffset) {
        wcscat_s(output, sizeof(output) / sizeof(output[0]), (wchar_t*)((PBYTE)eventInfo + eventInfo->ProviderNameOffset));
    }
    else {
        wcscat_s(output, sizeof(output) / sizeof(output[0]), L"Unknown");
    }
    wcscat_s(output, sizeof(output) / sizeof(output[0]), L";");*/

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

        case TDH_INTYPE_INT8:
            swprintf(output + wcslen(output), 32, L"%d;", *(PCHAR)propertyBuffer);
            break;
        case TDH_INTYPE_UINT8:
            swprintf(output + wcslen(output), 32, L"%u;", *(PUCHAR)propertyBuffer);
            break;
        case TDH_INTYPE_INT16:
            swprintf(output + wcslen(output), 32, L"%d;", *(PSHORT)propertyBuffer);
            break;
        case TDH_INTYPE_UINT16:
            swprintf(output + wcslen(output), 32, L"%u;", *(PUSHORT)propertyBuffer);
            break;
        case TDH_INTYPE_INT32:
            swprintf(output + wcslen(output), 32, L"%d;", *(PLONG)propertyBuffer);
            break;
        case TDH_INTYPE_INT64:
            swprintf(output + wcslen(output), 32, L"%lld;", *(PLONGLONG)propertyBuffer);
            break;
        case TDH_INTYPE_FLOAT:
            swprintf(output + wcslen(output), 32, L"%f;", *(PFLOAT)propertyBuffer);
            break;
        case TDH_INTYPE_DOUBLE:
            swprintf(output + wcslen(output), 32, L"%lf;", *(DOUBLE*)propertyBuffer);
            break;
        case TDH_INTYPE_BOOLEAN:
            swprintf(output + wcslen(output), 32, L"%d;", *(PBOOL)propertyBuffer);
            break;
        case TDH_INTYPE_BINARY: {
            // Print each byte in hexadecimal
            for (ULONG j = 0; j < bufferSize; j++) {
                swprintf(output + wcslen(output), 4, L"%02X", ((PBYTE)propertyBuffer)[j]);
            }
            wcscat_s(output, sizeof(output) / sizeof(output[0]), L";");
            break;
        }
        case TDH_INTYPE_GUID: {
            GUID* guid = (GUID*)propertyBuffer;
            swprintf(output + wcslen(output), 64, L"{%08x-%04x-%04x-%04x-%012x};", guid->Data1, guid->Data2, guid->Data3, *((USHORT*)guid->Data4), *((ULONG*)&guid->Data4[2]));
            break;
        }
        case TDH_INTYPE_SYSTEMTIME: {
            SYSTEMTIME* st = (SYSTEMTIME*)propertyBuffer;
            swprintf(output + wcslen(output), 64, L"%04d-%02d-%02d %02d:%02d:%02d;", st->wYear, st->wMonth, st->wDay, st->wHour, st->wMinute, st->wSecond);
            break;
        }
        case TDH_INTYPE_HEXINT32:
            swprintf(output + wcslen(output), 32, L"0x%08X;", *(PULONG)propertyBuffer);
            break;
        case TDH_INTYPE_HEXINT64:
            swprintf(output + wcslen(output), 32, L"0x%016llX;", *(PULONG64)propertyBuffer);
            break;
        case TDH_INTYPE_SID: {
            PSID sid = (PSID)propertyBuffer;
            WCHAR sidChar[256];
            LPWSTR sidString = (LPWSTR)sidChar;
            if (ConvertSidToStringSid(sid, &sidString)) {
                wcscat_s(output, sizeof(output) / sizeof(output[0]), sidString);
                wcscat_s(output, sizeof(output) / sizeof(output[0]), L";");
            }
            break;
        }

        default:
            swprintf(output + wcslen(output), 32, L"%d:0x%x;",
                eventInfo->EventPropertyInfoArray[i].nonStructType.InType,
                propertyBuffer
            );

            //wcscat_s(output, sizeof(output) / sizeof(output[0]), L"(Unknown type);");
            break;
        }

        free(propertyBuffer);
    }

    if (eventInfo) {
        free(eventInfo);
    }

    // Output the accumulated string
    //wprintf(L"%s\n", output);

//    SendEmitterPipe(output);
}


EVENT_TRACE_PROPERTIES* MakeSessionProperties(size_t session_name_len) {
    EVENT_TRACE_PROPERTIES* sessionProperties;
    ULONG bufferSize = (ULONG)(sizeof(EVENT_TRACE_PROPERTIES) + ((session_name_len + 1) * sizeof(wchar_t)));
    sessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    if (sessionProperties == NULL) {
        LOG_A(LOG_ERROR, "ETW: Allocating");
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