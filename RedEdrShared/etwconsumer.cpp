#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "logging.h"
#include "etwconsumer.h"


#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")


// Local data


// Local functions
EVENT_TRACE_PROPERTIES* MakeSessionProperties(size_t session_name_len);


EtwConsumer::EtwConsumer() {

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
    size_t len = mySessionName.length() + 1; // +1 for null terminator
    wchar_t* _sessionName = new wchar_t[len];
    wcscpy_s(_sessionName, len, mySessionName.c_str());
    SessionName = _sessionName;
    
    // Initialize handles (assuming INVALID_PROCESSTRACE_HANDLE and NULL are valid initial values)
    SessionHandle = NULL;
    TraceHandle = INVALID_PROCESSTRACE_HANDLE;

    if (CLSIDFromString(guid, &providerGuid) != NOERROR) {
        LOG_A(LOG_ERROR, "ETW: Invalid provider GUID format");
        return NULL;
    }
    wchar_t* sessionNameBuffer = _sessionName;

    // StartTrace -> SessionHandle
    EVENT_TRACE_PROPERTIES* sessionProperties = MakeSessionProperties(wcslen(sessionNameBuffer));
    status = StartTrace(&sessionHandle, sessionNameBuffer, sessionProperties);
    if (status == ERROR_ALREADY_EXISTS) {
        LOG_A(LOG_WARNING, "ETW: Session %ls already exists, attempt to stop it", mySessionName.c_str());
        StopEtw();
        Sleep(500);

        // Try it again...
        LOG_A(LOG_WARNING, "ETW: Attempt to open trace %ls again..", mySessionName.c_str());
        status = StartTrace(&sessionHandle, sessionNameBuffer, sessionProperties);
        if (status != ERROR_SUCCESS) {
            LOG_A(LOG_WARNING, "ETW: Failed to open session %ls", mySessionName.c_str());
            free(sessionProperties);
            return NULL;
        }
    }
    else if (status != ERROR_SUCCESS) {
        LOG_A(LOG_ERROR, "ETW: Failed to start trace: %d", status);
        free(sessionProperties);
        return NULL;
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
    traceLogfile.LoggerName = sessionNameBuffer;
    traceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLogfile.EventRecordCallback = func;
    traceHandle = OpenTrace(&traceLogfile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        LOG_A(LOG_ERROR, "ETW: Failed to open trace: %d", GetLastError());
        //delete[] sessionNameBuffer;
        free(sessionProperties);
        return NULL;
    }

    SessionHandle = sessionHandle;
    TraceHandle = traceHandle;

    free(sessionProperties);
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
    status = ControlTrace(SessionHandle, SessionName, sessionProperties, EVENT_TRACE_CONTROL_STOP);
    if (status != ERROR_SUCCESS) {
        LOG_A(LOG_WARNING, "ETW:     Failed to stop trace, error: %d", status);
    }
    else {
        LOG_A(LOG_INFO, "ETW:     ControlTrace stopped");
    }
    free(sessionProperties);

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
                << stLocal.wHour << L":" << stLocal.wMinute << L":" << stLocal.wSecond << L";";
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