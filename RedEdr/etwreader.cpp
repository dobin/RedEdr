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


struct Reader {
    int id;
    wchar_t* SessionName;
    TRACEHANDLE SessionHandle;
    TRACEHANDLE TraceHandle;
};

#define NUM_READERS 6
struct Reader Readers[NUM_READERS];


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
    //fflush(stdout);
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
    std::wstring eventName = L"engine";

    if (eventRecord == nullptr) {
        return;
    }
    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 60:
        // test:60;ProviderName:Microsoft-Antimalware-Engine;PID:187076;Channel:ThreatIntel;EventId:19;
        return;
    }

    // Rest
    PrintProperties(eventName, eventRecord);
}


void WINAPI EventRecordCallbackAntimalwareRtp(PEVENT_RECORD eventRecord) {
    std::wstring eventName = L"rtp";

    if (eventRecord == nullptr) {
        return;
    }
    switch (eventRecord->EventHeader.EventDescriptor.Id) {
    case 22:
        // test:22;ProviderName:Microsoft-Antimalware-RTP;Description:AsyncWorkerUpdate;PreviousValue:8;IntendedValueOrHResult:0;LatestValue:8;
        // test:22;ProviderName:Microsoft-Antimalware-RTP;Description:RevertPriorityOK;PreviousValue:8;IntendedValueOrHResult:14;LatestValue:14;
        return;
    }

    // Rest
    PrintProperties(eventName, eventRecord);
}


void WINAPI EventRecordCallbackPrintAll(PEVENT_RECORD eventRecord) {
    std::wstring eventName = L"test";

    if (eventRecord == nullptr) {
        return;
    }

    // All
    PrintProperties(eventName, eventRecord);
}


void EventTraceStopAll() {
    printf("--[ Stop tracing\n");
    ULONG status;
    EVENT_TRACE_PROPERTIES* sessionProperties;

    // Individual traces
    for (int n=0; n< NUM_READERS; n++) {
        printf("  Stop: %d...\n", n);
        Reader* reader = &Readers[n];
        sessionProperties = make_SessionProperties(wcslen(reader->SessionName));

        if (reader->SessionHandle != NULL) {
            status = ControlTrace(reader->SessionHandle, reader->SessionName, sessionProperties, EVENT_TRACE_CONTROL_STOP);
            if (status != ERROR_SUCCESS) {
                printf("Failed to stop trace %d: %d\n", n, status);
            }
            else {
                printf("    ControlTrace: %i stopped\n", n);
            }
            reader->SessionHandle = NULL;
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


BOOL setup_trace(Reader *reader, const wchar_t* guid, EventRecordCallbackFuncPtr func, const wchar_t* info) {
    ULONG status;
    GUID providerGuid;
    TRACEHANDLE sessionHandle;
    TRACEHANDLE traceHandle;

    printf("--[ Do Trace %i: %ls: %ls\n", reader->id, guid, info);

    if (CLSIDFromString(guid, &providerGuid) != NOERROR) {
        std::wcerr << L"Invalid provider GUID format." << std::endl;
        return false;
    }
    wchar_t* sessionNameBuffer = reader->SessionName;

    // StartTrace -> SessionHandle
    EVENT_TRACE_PROPERTIES* sessionProperties = make_SessionProperties(wcslen(sessionNameBuffer));
    status = StartTrace(&sessionHandle, sessionNameBuffer, sessionProperties);
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
        //delete[] sessionNameBuffer;
        free(sessionProperties);
        return false;
    }

    reader->SessionHandle = sessionHandle;
    reader->TraceHandle = traceHandle;

    free(sessionProperties);

    return TRUE;
}


DWORD WINAPI TraceProcessingThread(LPVOID param) {
    Reader *reader = (Reader*)param;
    printf("--[ Start Thread %i\n", reader->id);

    ULONG status = ProcessTrace(&reader->TraceHandle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS) {
        std::wcerr << L"Failed to process trace: " << status << std::endl;
    }
    return 0;
}


int EtwReader() {
    BOOL ret;
    DWORD status;

    printf("--[ Tracing session name: %ls\n", g_config.sessionName.c_str());

    // Initialize readers
    for (int i = 0; i < NUM_READERS; ++i) {
        Readers[i].id = i;

        // Allocate memory for the session name
        std::wstring mySessionName = g_config.sessionName + L"_" + std::to_wstring(i);
        size_t len = mySessionName.length() + 1; // +1 for null terminator
        wchar_t* sessionName = new wchar_t[len];
        wcscpy_s(sessionName, len, mySessionName.c_str());
        Readers[i].SessionName = sessionName;

        // Initialize handles (assuming INVALID_PROCESSTRACE_HANDLE and NULL are valid initial values)
        Readers[i].SessionHandle = NULL;
        Readers[i].TraceHandle = INVALID_PROCESSTRACE_HANDLE;
    }

    // Set up the console control handler to clean up on Ctrl+C
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        std::cerr << "Failed to set control handler" << std::endl;
        return 1;
    }

    ret = setup_trace(&Readers[0], L"{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}", &EventRecordCallbackKernelProcess, L"Microsoft-Windows-Kernel-Process");
    if (!ret) {
        printf("TODO ERROR\n");
        return 1;
    }
    ret = setup_trace(&Readers[1], L"{0a002690-3839-4e3a-b3b6-96d8df868d99}", &EventRecordCallbackAntimalwareEngine, L"Microsoft-Antimalware-Engine");
    if (!ret) {
        printf("TODO ERROR\n");
        return 1;
    }
    ret = setup_trace(&Readers[2], L"{8E92DEEF-5E17-413B-B927-59B2F06A3CFC}", &EventRecordCallbackAntimalwareRtp, L"Microsoft-Antimalware-RTP");
    if (!ret) {
        printf("TODO ERROR\n");
        return 1;
    }
    ret = setup_trace(&Readers[3], L"{CFEB0608-330E-4410-B00D-56D8DA9986E6}", &EventRecordCallbackPrintAll, L"Microsoft-Antimalware-AMFilter");
    if (!ret) {
        printf("TODO ERROR\n");
        return 1;
    }
    ret = setup_trace(&Readers[4], L"{2A576B87-09A7-520E-C21A-4942F0271D67}", &EventRecordCallbackPrintAll, L"Microsoft-Antimalware-Scan-Interface");
    if (!ret) {
        printf("TODO ERROR\n");
        return 1;
    }
    ret = setup_trace(&Readers[5], L"{e4b70372-261f-4c54-8fa6-a5a7914d73da}", &EventRecordCallbackPrintAll, L"Microsoft-Antimalware-Protection");
    if (!ret) {
        printf("TODO ERROR\n");
        return 1;
    }
    // Test
    /*ret = setup_trace(&Readers[2], L"{EDD08927-9CC4-4E65-B970-C2560FB5C289}", &EventRecordCallbackAntimalwareEngine, L"Microsoft-Windows-Kernel-File");
    if (!ret) {
        printf("TODO ERROR\n");
        return 1;
    }*/

    // ProcessTrace() can only handle 1 (one) real-time processing session
    // Create threads instead fuck...
    printf("---[ Start tracing...\n");
    std::vector<HANDLE> threads;
    for (size_t i = 0; i < NUM_READERS; ++i) {
        Reader* reader = &Readers[i];

        HANDLE thread = CreateThread(NULL, 0, TraceProcessingThread, reader, 0, NULL);
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
    for (int n = 0; n < NUM_READERS; n++) {
        Reader *reader = &Readers[n];

        if (reader->TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
            status = CloseTrace(reader->TraceHandle);
            if (status != ERROR_SUCCESS) {
                printf("Failed to close trace %d: %d\n", n, status);
            }
            else {
                printf("  CloseTrace: %i closed\n", n);
            }
            reader->TraceHandle = INVALID_PROCESSTRACE_HANDLE;
        }

        // Todo free memory
    }
}