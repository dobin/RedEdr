#include <Windows.h>
#include <iostream>
#include <vector>
#include <atomic>
#include <string>

#include <krabs.hpp>

#include "ppllogreader.h"
#include "logging.h"
#include "../Shared/common.h"


//
// RedEdr PPL service log ETW provider (TraceLogging), defined in the PPL
// service's logging.h. The GUID must match the one used by the service.
//
//   Provider name : "RedEdr-PplService-Log"
//   Provider GUID : 098bd1da-fc3b-46c0-becb-28b679f4a1a2
//
static const GUID REDEDR_PPL_LOG_PROVIDER_GUID =
{ 0x098bd1da, 0xfc3b, 0x46c0, { 0xbe, 0xcb, 0x28, 0xb6, 0x79, 0xf4, 0xa1, 0xa2 } };

// Dedicated trace session for PPL service log events.
static krabs::user_trace g_pplLogTrace(L"RedEdrPplLog");

static HANDLE g_hStopEvent = NULL;       // signaled to request thread stop
static HANDLE g_hReadyEvent = NULL;      // signaled when trace is ready
static HANDLE g_hThread = NULL;          // stored thread handle for join


//
// Map the PPL service's LOG_* severity (emitted as the "Severity" field) to a
// human-readable tag for the agent log line.
//
static const char* SeverityTag(UINT32 severity)
{
    switch (severity) {
    case LOG_ERROR:   return "ERROR";
    case LOG_WARNING: return "WARN";
    case LOG_INFO:    return "INFO";
    case LOG_DEBUG:   return "DEBUG";
    default:          return "LOG";
    }
}


//
// Handle a single TraceLogging "Log" event from the PPL service.
//
// The event has two properties:
//   - "Message"  : ANSI string (the formatted log line)
//   - "Severity" : UInt32 (LOG_* value from Shared/common.h)
//
static void OnPplLogEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context)
{
    try {
        krabs::schema schema(record, trace_context.schema_locator);
        krabs::parser parser(schema);

        std::string message;
        UINT32 severity = LOG_INFO;

        for (const auto& prop : parser.properties()) {
            const std::wstring& name = prop.name();
            if (name == L"Message") {
                if (prop.type() == TDH_INTYPE_ANSISTRING) {
                    message = parser.parse<std::string>(name);
                }
            }
            else if (name == L"Severity") {
                if (prop.type() == TDH_INTYPE_UINT32) {
                    severity = parser.parse<UINT32>(name);
                }
            }
        }

        if (message.empty()) {
            return;
        }

        // Prefix with source + severity so the line is identifiable in the
        // combined agent log alongside RedEdr's own LOG_A output.
        std::string line = "[PPL] [";
        line += SeverityTag(severity);
        line += "] ";
        line += message;

        AddAgentLog(line);
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "PplLogReader: event parse exception: %s", e.what());
    }
    catch (...) {
        LOG_A(LOG_ERROR, "PplLogReader: event parse unknown exception");
    }
}


DWORD WINAPI PplLogReaderThread(LPVOID param)
{
    UNREFERENCED_PARAMETER(param);

    try {
        krabs::provider<> pplLogProvider(REDEDR_PPL_LOG_PROVIDER_GUID);
        pplLogProvider.add_on_event_callback(OnPplLogEvent);
        g_pplLogTrace.enable(pplLogProvider);

        LOG_A(LOG_INFO, "PplLogReader: provider enabled (RedEdr-PplService-Log)");

        // Signal readiness before entering the blocking start().
        SetEvent(g_hReadyEvent);

        // Blocking; stopped via g_pplLogTrace.stop() from PplLogReaderShutdown.
        g_pplLogTrace.start();
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "PplLogReader: thread exception: %s", e.what());
        if (g_hReadyEvent != NULL) {
            SetEvent(g_hReadyEvent);
        }
    }
    catch (...) {
        LOG_A(LOG_ERROR, "PplLogReader: thread unknown exception");
        if (g_hReadyEvent != NULL) {
            SetEvent(g_hReadyEvent);
        }
    }

    LOG_A(LOG_DEBUG, "PplLogReader: thread finished");
    return 0;
}


BOOL PplLogReaderInit(std::vector<HANDLE>& threads)
{
    g_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_hStopEvent == NULL) {
        LOG_A(LOG_ERROR, "PplLogReader: failed to create stop event");
        return FALSE;
    }

    g_hReadyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_hReadyEvent == NULL) {
        LOG_A(LOG_ERROR, "PplLogReader: failed to create ready event");
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
        return FALSE;
    }

    HANDLE thread = CreateThread(NULL, 0, PplLogReaderThread, NULL, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "PplLogReader: failed to create thread");
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
        CloseHandle(g_hReadyEvent);
        g_hReadyEvent = NULL;
        return FALSE;
    }
    g_hThread = thread;

    // Wait until the trace session is fully initialized before returning, so
    // callers can immediately start the PPL service and not miss any startup
    // log events.
    WaitForSingleObject(g_hReadyEvent, INFINITE);

    LOG_A(LOG_DEBUG, "PplLogReader: thread started");
    threads.push_back(thread);
    return TRUE;
}


void PplLogReaderShutdown()
{
    // Stop the blocking trace.start() in the reader thread.
    g_pplLogTrace.stop();

    if (g_hStopEvent != NULL) {
        SetEvent(g_hStopEvent);
    }

    if (g_hThread != NULL) {
        if (WaitForSingleObject(g_hThread, 5000) == WAIT_TIMEOUT) {
            LOG_A(LOG_WARNING, "PplLogReader: thread did not exit in time, force-terminating");
            TerminateThread(g_hThread, 1);
        }
        CloseHandle(g_hThread);
        g_hThread = NULL;
    }

    if (g_hStopEvent != NULL) {
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
    }
    if (g_hReadyEvent != NULL) {
        CloseHandle(g_hReadyEvent);
        g_hReadyEvent = NULL;
    }
}
