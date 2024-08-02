#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "etwreader.h"
#include "cache.h"
#include "config.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")


void EnableProvider(TRACEHANDLE sessionHandle, const GUID& providerGuid) {
    ULONG status = EnableTraceEx2(
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
        std::wcerr << L"Failed to enable provider: " << status << std::endl;
    }
}

void DeleteTraceSession(const std::wstring& sessionName) {
    EVENT_TRACE_PROPERTIES* sessionProperties = nullptr;
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (sessionName.size() + 1) * sizeof(wchar_t);

    sessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    ZeroMemory(sessionProperties, bufferSize);

    sessionProperties->Wnode.BufferSize = bufferSize;
    sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = ControlTrace(NULL, sessionName.c_str(), sessionProperties, EVENT_TRACE_CONTROL_STOP);
    if (status != ERROR_SUCCESS && status != ERROR_WMI_INSTANCE_NOT_FOUND) {
        std::wcerr << L"Failed to delete trace session: " << status << std::endl;
    }
    else {
        std::wcout << L"Trace session deleted successfully." << std::endl;
    }

    free(sessionProperties);
}


void PrintProperties(std::wstring eventName, PEVENT_RECORD eventRecord) {
    DWORD bufferSize = 0;
    PTRACE_EVENT_INFO eventInfo = NULL;
    TDHSTATUS status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    if (status == ERROR_INSUFFICIENT_BUFFER) {
        eventInfo = (PTRACE_EVENT_INFO)malloc(bufferSize);
        status = TdhGetEventInformation(eventRecord, 0, NULL, eventInfo, &bufferSize);
    }
    if (ERROR_SUCCESS != status) {
        if (eventInfo) {
            free(eventInfo);
        }
        return;
    }

    // String stream to accumulate output
    std::wstringstream output;
    output << eventName << ":" << eventRecord->EventHeader.EventDescriptor.Id << L";";

    //output << L"EventID:" << eventRecord->EventHeader.EventDescriptor.Id << L";";
    output << L"ProviderName:" << (eventInfo->ProviderNameOffset ? (PCWSTR)((PBYTE)eventInfo + eventInfo->ProviderNameOffset) : L"Unknown") << L";";

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
        case TDH_INTYPE_POINTER:
            output << reinterpret_cast<PVOID>(propertyBuffer.data()) << L";";
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

    // Print the accumulated string
    std::wcout << output.str() << L"\n";
    fflush(stdout);
}


void WINAPI EventRecordCallback(PEVENT_RECORD eventRecord) {
    std::wstring eventName;

    if (eventRecord == nullptr) {
        return;
    }

    // Do we want to track this process?
    DWORD processId = eventRecord->EventHeader.ProcessId;
    if (!g_cache.observe(processId)) {
        return;
    }

    // This is exclusively for Microsoft-Windows-Kernel-Process provider, change the Event IDs for other providers
    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 1:  // Process Start
        eventName = L"StartProcess";
        break;
    case 3:  // Thread Start
        eventName = L"StartThread";
        break;
    case 5:  // Image Load
        eventName = L"LoadImage";
        break;
    default:
        if (g_config.log_unload) {
            switch (eventRecord->EventHeader.EventDescriptor.Id) {
            case 2:  // Process Stop
                eventName = L"StopProcess";
                break;
            case 4:  // Thread Stop
                eventName = L"StopThread";
                break;
                break;
            case 6:  // Image Unload
                eventName = L"UnloadImage";
                break;
            default:
                // Ignore other events
                return;
            }
        }
        else {
            return;
        }
    }
    
    PrintProperties(eventName, eventRecord);
}

TRACEHANDLE g_hTraceHandle = INVALID_PROCESSTRACE_HANDLE; // Global trace handle
std::wstring sessionName = g_config.sessionName;
TRACEHANDLE sessionHandle = 0;
EVENT_TRACE_PROPERTIES* sessionProperties = nullptr;


void stop() {
    printf("ControlTrace\n"); fflush(stdout);
    ULONG status;

    status = ControlTrace(sessionHandle, sessionName.c_str(), sessionProperties, EVENT_TRACE_CONTROL_STOP);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to stop trace: " << status << std::endl;
    }

    // Stop the trace session if it's active
    if (g_hTraceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(g_hTraceHandle);
        g_hTraceHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    DeleteTraceSession(sessionName);
}

BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        std::wcout << L"Cleaning up resources..." << std::endl;
        stop();
        return TRUE; // Indicate that we handled the signal
    default:
        return FALSE; // Let the next handler handle the signal
    }
}

int etwreader() {
    ULONG status;

    // Set up the console control handler to clean up on Ctrl+C
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        std::cerr << "Failed to set control handler" << std::endl;
        return 1;
    }

    GUID providerGuid;
    if (CLSIDFromString(L"{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}", &providerGuid) != NOERROR) {
        std::wcerr << L"Invalid provider GUID format." << std::endl;
        return 1;
    }

    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + (sessionName.size() + 1) * sizeof(wchar_t);

    sessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    ZeroMemory(sessionProperties, bufferSize);

    sessionProperties->Wnode.BufferSize = bufferSize;
    sessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    sessionProperties->Wnode.ClientContext = 1;  // QPC clock resolution
    sessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    status = StartTrace(&sessionHandle, sessionName.c_str(), sessionProperties);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to start trace: " << status << std::endl;
        free(sessionProperties);
        return 1;
    }

    EnableProvider(sessionHandle, providerGuid);

    wchar_t* sessionNameBuffer = new wchar_t[sessionName.size() + 1];
    wcscpy_s(sessionNameBuffer, sessionName.size() + 1, sessionName.c_str());

    EVENT_TRACE_LOGFILE traceLogfile;
    ZeroMemory(&traceLogfile, sizeof(EVENT_TRACE_LOGFILE));
    traceLogfile.LoggerName = sessionNameBuffer;
    traceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLogfile.EventRecordCallback = EventRecordCallback;

    g_hTraceHandle = OpenTrace(&traceLogfile);
    if (g_hTraceHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::wcerr << L"Failed to open trace: " << GetLastError() << std::endl;
        delete[] sessionNameBuffer;
        free(sessionProperties);
        return 1;
    }

    status = ProcessTrace(&g_hTraceHandle, 1, 0, 0);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to process trace: " << status << std::endl;
    }

    //CloseTrace(g_hTraceHandle);
    delete[] sessionNameBuffer;
    free(sessionProperties);
    return 0;
}
