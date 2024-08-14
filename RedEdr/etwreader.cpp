#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "loguru.hpp"
#include "etwreader.h"
#include "cache.h"
#include "config.h"
#include "etwhandler.h"

#pragma comment(lib, "tdh.lib")
#pragma comment(lib, "advapi32.lib")


#define NUM_READERS 1 // 7
struct Reader Readers[NUM_READERS];


// Entry function
int InitializeEtwReader(std::vector<HANDLE>& threads) {
    BOOL ret;
    DWORD status;

    LOG_F(INFO, "--[ Tracing session name: %ls", g_config.sessionName.c_str());

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

    ret = setup_trace(&Readers[0], L"{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}", &EventRecordCallbackKernelProcess, L"Microsoft-Windows-Kernel-Process");
    if (!ret) {
        LOG_F(ERROR, "TODO ERROR");
        return 1;
    }
    if (NUM_READERS > 1) {
        ret = setup_trace(&Readers[1], L"{0a002690-3839-4e3a-b3b6-96d8df868d99}", &EventRecordCallbackAntimalwareEngine, L"Microsoft-Antimalware-Engine");
        if (!ret) {
            LOG_F(ERROR, "TODO ERROR");
            return 1;
        }
    }
    if (NUM_READERS > 2) {
        ret = setup_trace(&Readers[2], L"{8E92DEEF-5E17-413B-B927-59B2F06A3CFC}", &EventRecordCallbackAntimalwareRtp, L"Microsoft-Antimalware-RTP");
        if (!ret) {
            LOG_F(ERROR, "TODO ERROR");
            return 1;
        }
    }
    if (NUM_READERS > 3) {
        ret = setup_trace(&Readers[3], L"{CFEB0608-330E-4410-B00D-56D8DA9986E6}", &EventRecordCallbackPrintAll, L"Microsoft-Antimalware-AMFilter");
        if (!ret) {
            LOG_F(ERROR, "TODO ERROR");
            return 1;
        }
    }
    if (NUM_READERS > 4) {
        ret = setup_trace(&Readers[4], L"{2A576B87-09A7-520E-C21A-4942F0271D67}", &EventRecordCallbackPrintAll, L"Microsoft-Antimalware-Scan-Interface");
        if (!ret) {
            LOG_F(ERROR, "TODO ERROR");
            return 1;
        }
    }
    if (NUM_READERS > 5) {
        ret = setup_trace(&Readers[5], L"{e4b70372-261f-4c54-8fa6-a5a7914d73da}", &EventRecordCallbackPrintAll, L"Microsoft-Antimalware-Protection");
        if (!ret) {
            LOG_F(ERROR, "TODO ERROR");
            return 1;
        }
    }
    if (NUM_READERS > 6) {
        ret = setup_trace_security_auditing(&Readers[6]);
        if (!ret) {
            LOG_F(ERROR, "TODO ERROR");
            return 1;
        }
    }
    // Test
    /*ret = setup_trace(&Readers[2], L"{EDD08927-9CC4-4E65-B970-C2560FB5C289}", &EventRecordCallbackAntimalwareEngine, L"Microsoft-Windows-Kernel-File");
    if (!ret) {
        LOG_F(ERROR, "TODO ERROR");
        return 1;
    }*/

    // ProcessTrace() can only handle 1 (one) real-time processing session
    // Create threads instead fuck...
    LOG_F(INFO, "---[ Start tracing...");
    for (size_t i = 0; i < NUM_READERS; ++i) {
        Reader* reader = &Readers[i];

        HANDLE thread = CreateThread(NULL, 0, TraceProcessingThread, reader, 0, NULL);
        if (thread == NULL) {
            LOG_F(ERROR, "Failed to create thread for trace session %i", i);
            return 1;
        }
        threads.push_back(thread);
    }

    LOG_F(INFO, "---[ All threads created");

    return 0;
}


void EtwReaderStopAll() {
    /*
    The ProcessTrace function blocks the thread until
      it delivers all events,
      the BufferCallback function returns FALSE,
      or you call CloseTrace.
    In addition, if the consumer is consuming events in real time, the ProcessTrace
    function returns after the controller stops the trace session.
    (Note that there may be a delay of several seconds before the function returns.)
    */
    LOG_F(INFO, "--[ Stopping EtwTracing"); fflush(stdout);
    ULONG status;
    EVENT_TRACE_PROPERTIES* sessionProperties;

    // Stop trace sessions
    for (int n = 0; n < NUM_READERS; n++) {
        Reader* reader = &Readers[n];
        sessionProperties = make_SessionProperties(wcslen(reader->SessionName));

        if (reader->SessionHandle != NULL) {
            LOG_F(INFO, "  Stop Session with ControlTrace(EVENT_TRACE_CONTROL_STOP): %d", n);
            status = ControlTrace(reader->SessionHandle, reader->SessionName, sessionProperties, EVENT_TRACE_CONTROL_STOP);
            if (status != ERROR_SUCCESS) {
                LOG_F(WARNING, "    Failed to stop trace %d: %d", n, status);
            }
            else {
                LOG_F(INFO, "    ControlTrace: %i stopped", n);
            }
            reader->SessionHandle = NULL;
        }
        else {
            // Kill thread?
        }
        free(sessionProperties);

        fflush(stdout);
    }

    LOG_F(INFO, "Tracing finished, cleanup..."); fflush(stdout);
    Sleep(2000);
    // NOTE if shit is still printing on screen, the following may fail?

    // TODO This should be done after all EtwReader threads exited?
    for (int n = 0; n < NUM_READERS; n++) {
        Reader* reader = &Readers[n];
        // Stop the traces
        if (reader->TraceHandle != INVALID_PROCESSTRACE_HANDLE) {
            LOG_F(INFO, "  CloseTrace(): %i", n);

            status = CloseTrace(reader->TraceHandle);
            if (status == ERROR_CTX_CLOSE_PENDING) {
                // The call was successful. The ProcessTrace function will stop 
                // after it has processed all real-time events in its buffers 
                // (it will not receive any new events).
                LOG_F(INFO, "    CloseTrace() success but pending");
                LOG_F(INFO, "    Lets sleep a bit");
                fflush(stdout);
                Sleep(3000);
            }
            else if (status == ERROR_SUCCESS) {
                LOG_F(INFO, "    CloseTrace() success");
            }
            else {
                LOG_F(WARNING, "    CloseTrace() failed: %d", status);
            }
            reader->TraceHandle = INVALID_PROCESSTRACE_HANDLE;
        }

        // Todo free memory

        fflush(stdout);
    }
    LOG_F(INFO, "--[ EtwTracing all stopped"); fflush(stdout);
}


BOOL setup_trace(Reader* reader, const wchar_t* guid, EventRecordCallbackFuncPtr func, const wchar_t* info) {
    ULONG status;
    GUID providerGuid;
    TRACEHANDLE sessionHandle;
    TRACEHANDLE traceHandle;

    LOG_F(INFO, "--[ Do Trace %i: %ls: %ls", reader->id, guid, info);

    if (CLSIDFromString(guid, &providerGuid) != NOERROR) {
        LOG_F(ERROR, "Invalid provider GUID format");
        return false;
    }
    wchar_t* sessionNameBuffer = reader->SessionName;

    // StartTrace -> SessionHandle
    EVENT_TRACE_PROPERTIES* sessionProperties = make_SessionProperties(wcslen(sessionNameBuffer));
    status = StartTrace(&sessionHandle, sessionNameBuffer, sessionProperties);
    if (status != ERROR_SUCCESS) {
        LOG_F(ERROR, "Failed to start trace: %d", status);
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
    traceLogfile.EventRecordCallback = func;
    traceHandle = OpenTrace(&traceLogfile);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        LOG_F(ERROR, "Failed to open trace: %d", GetLastError());
        //delete[] sessionNameBuffer;
        free(sessionProperties);
        return false;
    }

    reader->SessionHandle = sessionHandle;
    reader->TraceHandle = traceHandle;

    free(sessionProperties);

    return TRUE;
}

// Microsoft-Windows-Security-Auditing is different
// https://github.com/microsoft/krabsetw/blob/e39e9b766a2b77a5266f0ab4b776e0ca367b3409/examples/NativeExamples/user_trace_005.cpp#L4
// https://github.com/microsoft/krabsetw/issues/79
// https://github.com/microsoft/krabsetw/issues/5
BOOL setup_trace_security_auditing(Reader* reader) {
    // Check: Are we system?
    char user_name[128] = { 0 };
    DWORD user_name_length = 128;
    if (!GetUserNameA(user_name, &user_name_length) || strcmp(user_name, "SYSTEM") != 0)
    {
        LOG_F(ERROR, "Microsoft-Windows-Security-Auditing can only be traced by SYSTEM");
        return FALSE;
    }
    LOG_F(INFO, "--[ Do Trace %i: %ls: %ls", reader->id, L"{54849625-5478-4994-A5BA-3E3B0328C30D}", L"Microsoft-Windows-Security-Auditing");

    // Only one trace session is allowed for this provider: "EventLog-Security"
    // Open a handle to this trace session
    EVENT_TRACE_LOGFILE trace;
    ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));
    trace.LoggerName = const_cast<LPWSTR>(L"EventLog-Security");
    trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
    trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(EventRecordCallbackSecurityAuditing);

    // Open trace
    TRACEHANDLE traceHandle = OpenTrace(&trace);
    if (traceHandle == INVALID_PROCESSTRACE_HANDLE) {
        LOG_F(ERROR, "Failed to open trace. Error: %d", GetLastError());
        return FALSE;
    }

    DWORD x = ERROR_CTX_CLOSE_PENDING;
    reader->SessionHandle = NULL;  // Dont have no session
    reader->TraceHandle = traceHandle;

    return TRUE;
}


/** Helpers **/

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
        LOG_F(ERROR, "Failed to enable provider: %d", status);
    }
}


DWORD WINAPI TraceProcessingThread(LPVOID param) {
    Reader *reader = (Reader*)param;
    LOG_F(INFO, "--[ Start Thread %i", reader->id);

    ULONG status = ProcessTrace(&reader->TraceHandle, 1, NULL, NULL);
    if (status != ERROR_SUCCESS) {
        LOG_F(ERROR, "Failed to process trace: %d", status);
    }
    LOG_F(INFO, "--[ Exit Thread %i", reader->id);
    return 0;
}

