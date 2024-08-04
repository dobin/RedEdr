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


TRACEHANDLE SessionHandles[] = {
    NULL,
    NULL,
};

TRACEHANDLE TraceHandles[] = {
    INVALID_PROCESSTRACE_HANDLE,
    INVALID_PROCESSTRACE_HANDLE
};

wchar_t* SessionNames[] = {
    NULL,
    NULL
};


EVENT_TRACE_PROPERTIES* make_SessionProperties(int session_name_len) {
    EVENT_TRACE_PROPERTIES* sessionProperties;
    ULONG bufferSize = sizeof(EVENT_TRACE_PROPERTIES) + ((session_name_len + 1) * sizeof(wchar_t));
    sessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(bufferSize);
    ZeroMemory(sessionProperties, bufferSize);
    sessionProperties->Wnode.BufferSize = bufferSize;
    sessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    sessionProperties->Wnode.ClientContext = 1;  // QPC clock resolution
    sessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    sessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    return sessionProperties;
}


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


void WINAPI EventRecordCallbackKernelProcess(PEVENT_RECORD eventRecord) {
    std::wstring eventName;

    if (eventRecord == nullptr) {
        return;
    }

    // Do we want to track this process?
    DWORD processId = eventRecord->EventHeader.ProcessId;
    if (!g_cache.observe(processId)) {
        return;
    }

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


void WINAPI EventRecordCallbackAntimalwareEngine(PEVENT_RECORD eventRecord) {
    std::wstring eventName = L"test";

    if (eventRecord == nullptr) {
        return;
    }

    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 12: // or 14, 16
        PrintProperties(eventName, eventRecord);
    default:
        return;
    }

    PrintProperties(eventName, eventRecord);
}


void EventTraceStopAll() {
    printf("--[ Stop tracing\n"); fflush(stdout);
    ULONG status;
    EVENT_TRACE_PROPERTIES* sessionProperties;

    // Individual traces
    for (int n=0; n<2; n++) {
        printf("  Stop: %d...\n", n);
        sessionProperties = make_SessionProperties(wcslen(SessionNames[n]));

        if (SessionHandles[n] != NULL) {
            status = ControlTrace(SessionHandles[n], SessionNames[n], sessionProperties, EVENT_TRACE_CONTROL_STOP);
            if (status != ERROR_SUCCESS) {
                printf("Failed to stop trace %d: %d\n", n, status);
            }
            else {
                printf("    ControlTrace: %i stopped\n", n);
            }
            SessionHandles[n] = NULL;
        }
        free(sessionProperties);
    }
}


BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        std::wcout << L"Cleaning up resources..." << std::endl;
        EventTraceStopAll();
        return TRUE; // Indicate that we handled the signal
    default:
        return FALSE; // Let the next handler handle the signal
    }
}

typedef void (WINAPI* EventRecordCallbackFuncPtr)(PEVENT_RECORD);


BOOL do_trace(int idx, const wchar_t* guid, EventRecordCallbackFuncPtr func, const wchar_t* info) {
    ULONG status;
    GUID providerGuid;
    TRACEHANDLE sessionHandle;
    TRACEHANDLE traceHandle;

    printf("--[ Do Trace %i: %ls: %ls\n", idx, guid, info);

    if (CLSIDFromString(guid, &providerGuid) != NOERROR) {
        std::wcerr << L"Invalid provider GUID format." << std::endl;
        return false;
    }
    std::wstring mySessionName = g_config.sessionName + L"_" + std::to_wstring(idx);
    wchar_t* sessionNameBuffer = new wchar_t[mySessionName.size() + 1];
    wcscpy_s(sessionNameBuffer, mySessionName.size() + 1, mySessionName.c_str());

    // StartTrace -> SessionHandle
    EVENT_TRACE_PROPERTIES* sessionProperties = make_SessionProperties(wcslen(sessionNameBuffer));
    status = StartTrace(&sessionHandle, mySessionName.c_str(), sessionProperties);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to start trace: " << status << std::endl;
        free(sessionProperties);
        return false;
    }

    // EnableProvider
    EnableProvider(sessionHandle, providerGuid);

    // OpenTrace
    EVENT_TRACE_LOGFILE traceLogfile;
    ZeroMemory(&traceLogfile, sizeof(EVENT_TRACE_LOGFILE));
    traceLogfile.LoggerName = sessionNameBuffer;
    traceLogfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    traceLogfile.EventRecordCallback = func; //EventRecordCallbackKernelProcess;
    traceHandle = OpenTrace(&traceLogfile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        std::wcerr << L"Failed to open trace: " << GetLastError() << std::endl;
        delete[] sessionNameBuffer;
        free(sessionProperties);
        return false;
    }

    SessionHandles[idx] = sessionHandle;
    TraceHandles[idx] = traceHandle;
    SessionNames[idx] = sessionNameBuffer;

    //delete[] sessionNameBuffer;
    free(sessionProperties);

    return TRUE;
}


DWORD WINAPI TraceProcessingThread(LPVOID param) {
    printf("Start Thread...\n");
    TRACEHANDLE traceHandle = *(TRACEHANDLE*)param;
    ULONG status = ProcessTrace(&traceHandle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to process trace: " << status << std::endl;
    }
    return 0;
}


int EtwReader() {
    BOOL ret;
    DWORD status;

    printf("--[ Tracing session name: %ls\n", g_config.sessionName.c_str());

    // Set up the console control handler to clean up on Ctrl+C
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        std::cerr << "Failed to set control handler" << std::endl;
        return 1;
    }

    ret = do_trace(0, L"{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}", &EventRecordCallbackKernelProcess, L"Microsoft-Windows-Kernel-Process");
    if (!ret) {
        printf("TODO ERROR\n");
        return 1;
    }
    //do_trace(L"{0a002690-3839-4e3a-b3b6-96d8df868d99}", &EventRecordCallbackAntimalwareEngine, L"Microsoft-Antimalware-Engine");
    //do_trace(L"{e4b70372-261f-4c54-8fa6-a5a7914d73da}", &EventRecordCallbackAntimalwareEngine, L"Microsoft-Antimalware-Protection");
    ret = do_trace(1, L"{EDD08927-9CC4-4E65-B970-C2560FB5C289}", &EventRecordCallbackAntimalwareEngine, L"Microsoft-Windows-Kernel-File");
    if (!ret) {
        printf("TODO ERROR\n");
        return 1;
    }

    // ProcessTrace() can only handle 1 (one) real-time processing session
    // Create threads instead fuck...
    printf("---[ Start tracing...\n");
    std::vector<HANDLE> threads;
    for (size_t i = 0; i < 2; ++i) {
        HANDLE thread = CreateThread(NULL, 0, TraceProcessingThread, &TraceHandles[i], 0, NULL);
        if (thread == NULL) {
            std::wcerr << L"Failed to create thread for trace session " << i << std::endl;
            return 1;
        }
        threads.push_back(thread);
    }

    // Wait for all threads to complete
    // Stop via ctrl-c: ControlTrace EVENT_TRACE_CONTROL_STOP all, which makes the threads return
    WaitForMultipleObjects(threads.size(), threads.data(), TRUE, INFINITE);

    printf("Tracing finished, cleanup...\n");
    for (int n = 0; n < 2; n++) {
        if (TraceHandles[n] != INVALID_PROCESSTRACE_HANDLE) {
            status = CloseTrace(TraceHandles[n]);
            if (status != ERROR_SUCCESS) {
                printf("Failed to close trace %d: %d\n", n, status);
                //std::wcerr << L"Failed to close trace: " << status << std::endl;
            }
            else {
                printf("  CloseTrace: %i closed\n", n);
            }
            TraceHandles[n] = INVALID_PROCESSTRACE_HANDLE;
        }
    }
}