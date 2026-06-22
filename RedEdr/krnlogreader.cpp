#include <Windows.h>
#include <iostream>
#include <vector>
#include <atomic>
#include <string>

#include <krabs.hpp>

#include "krnlogreader.h"
#include "logging.h"
#include "../Shared/common.h"


//
// RedEdr kernel-log ETW provider (TraceLogging), defined in the driver's
// etwlog.h. The GUID must match the one used by the driver exactly.
//
//   Provider name : "RedEdr-Kernel-Log"
//   Provider GUID : 07a19134-15d7-4601-b106-4b7a7aafc582
//
static const GUID REDEDR_KRN_LOG_PROVIDER_GUID =
{ 0x07a19134, 0x15d7, 0x4601, { 0xb1, 0x06, 0x4b, 0x7a, 0x7a, 0xaf, 0xc5, 0x82 } };

// Dedicated trace session for kernel log events. Kept separate from the main
// RedEdrUser trace in etwreader.cpp so this reader can be started/stopped
// independently and early (before the main ETW reader is configured).
static krabs::user_trace g_krnLogTrace(L"RedEdrKrnLog");

static HANDLE g_hStopEvent = NULL;       // signaled to request thread stop
static HANDLE g_hReadyEvent = NULL;      // signaled when trace is ready
static HANDLE g_hThread = NULL;          // stored thread handle for join


//
// Map the driver's LOG_* severity (emitted as the "Severity" field) to a
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
// Handle a single TraceLogging "Log" event from the kernel driver.
//
// The event has two properties:
//   - "Message"  : ANSI string (the formatted log line)
//   - "Severity" : UInt32 (LOG_* value from Shared/common.h)
//
static void OnKrnLogEvent(const EVENT_RECORD& record, const krabs::trace_context& trace_context)
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
        std::string line = "[KRN] [";
        line += SeverityTag(severity);
        line += "] ";
        line += message;

        AddAgentLog(line);
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "KrnLogReader: event parse exception: %s", e.what());
    }
    catch (...) {
        LOG_A(LOG_ERROR, "KrnLogReader: event parse unknown exception");
    }
}


DWORD WINAPI KrnLogReaderThread(LPVOID param)
{
    UNREFERENCED_PARAMETER(param);

    try {
        krabs::provider<> krnLogProvider(REDEDR_KRN_LOG_PROVIDER_GUID);
        // Capture all levels (the driver maps LOG_* -> WINEVENT_LEVEL_*).
        krnLogProvider.trace_flags(krnLogProvider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        krnLogProvider.add_on_event_callback(OnKrnLogEvent);
        g_krnLogTrace.enable(krnLogProvider);

        LOG_A(LOG_INFO, "KrnLogReader: provider enabled (RedEdr-Kernel-Log)");

        // Signal readiness before entering the blocking start().
        SetEvent(g_hReadyEvent);

        // Blocking; stopped via g_krnLogTrace.stop() from KrnLogReaderShutdown.
        g_krnLogTrace.start();
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "KrnLogReader: thread exception: %s", e.what());
        if (g_hReadyEvent != NULL) {
            SetEvent(g_hReadyEvent);
        }
    }
    catch (...) {
        LOG_A(LOG_ERROR, "KrnLogReader: thread unknown exception");
        if (g_hReadyEvent != NULL) {
            SetEvent(g_hReadyEvent);
        }
    }

    LOG_A(LOG_DEBUG, "KrnLogReader: thread finished");
    return 0;
}


BOOL KrnLogReaderInit(std::vector<HANDLE>& threads)
{
    g_hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_hStopEvent == NULL) {
        LOG_A(LOG_ERROR, "KrnLogReader: failed to create stop event");
        return FALSE;
    }

    g_hReadyEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (g_hReadyEvent == NULL) {
        LOG_A(LOG_ERROR, "KrnLogReader: failed to create ready event");
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
        return FALSE;
    }

    HANDLE thread = CreateThread(NULL, 0, KrnLogReaderThread, NULL, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "KrnLogReader: failed to create thread");
        CloseHandle(g_hStopEvent);
        g_hStopEvent = NULL;
        CloseHandle(g_hReadyEvent);
        g_hReadyEvent = NULL;
        return FALSE;
    }
    g_hThread = thread;

    // Wait until the trace session is fully initialized before returning, so
    // callers can immediately load/configure the kernel driver and not miss
    // any DriverEntry log events.
    WaitForSingleObject(g_hReadyEvent, INFINITE);

    LOG_A(LOG_DEBUG, "KrnLogReader: thread started");
    threads.push_back(thread);
    return TRUE;
}


void KrnLogReaderShutdown()
{
    // Stop the blocking trace.start() in the reader thread.
    g_krnLogTrace.stop();

    if (g_hStopEvent != NULL) {
        SetEvent(g_hStopEvent);
    }

    if (g_hThread != NULL) {
        if (WaitForSingleObject(g_hThread, 5000) == WAIT_TIMEOUT) {
            LOG_A(LOG_WARNING, "KrnLogReader: thread did not exit in time, force-terminating");
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
