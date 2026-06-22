#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>

#include "logging.h"
#include "../Shared/common.h"

// Define the provider exactly once, in this translation unit.
TRACELOGGING_DEFINE_PROVIDER(
    g_RedEdrPplLogProvider,
    "RedEdr-PplService-Log",
    (0x098bd1da, 0xfc3b, 0x46c0, 0xbe, 0xcb, 0x28, 0xb6, 0x79, 0xf4, 0xa1, 0xa2));


//
// Severity -> ETW level mapping.
//
// LOG_* values come from Shared/common.h:
//   LOG_ERROR   0
//   LOG_WARNING 1
//   LOG_INFO    2
//   LOG_DEBUG   3
//
// ETW levels (WINEVENT_LEVEL_*):
//   WINEVENT_LEVEL_ERROR    2
//   WINEVENT_LEVEL_WARNING  3
//   WINEVENT_LEVEL_INFO     4
//   WINEVENT_LEVEL_VERBOSE  5
//
// ETW level numeric values (from winmeta.h / evntrace.h):
//   TRACE_LEVEL_CRITICAL  1
//   TRACE_LEVEL_ERROR     2
//   TRACE_LEVEL_WARNING   3
//   TRACE_LEVEL_INFORMATION 4
//   TRACE_LEVEL_VERBOSE   5
static UCHAR SeverityToEtwLevel(int severity)
{
    switch (severity) {
    case LOG_ERROR:   return 2; // TRACE_LEVEL_ERROR
    case LOG_WARNING: return 3; // TRACE_LEVEL_WARNING
    case LOG_INFO:    return 4; // TRACE_LEVEL_INFORMATION
    case LOG_DEBUG:   return 5; // TRACE_LEVEL_VERBOSE
    default:          return 4;
    }
}


// TraceLoggingLevel() requires a compile-time constant, so we dispatch on
// severity and hardcode the level in each TraceLoggingWrite call.
#define PPL_LOG_WRITE(lvl, msg, sev) \
    TraceLoggingWrite(g_RedEdrPplLogProvider, "Log", \
        TraceLoggingLevel(lvl), \
        TraceLoggingValue(msg, "Message"), \
        TraceLoggingValue((UINT32)(sev), "Severity"), \
        TraceLoggingKeyword(0))

static void LogEtwEvent(int severity, const char* message)
{
    if (message == NULL) {
        return;
    }

    switch (severity) {
    case LOG_ERROR:   PPL_LOG_WRITE(2, message, severity); break; // TRACE_LEVEL_ERROR
    case LOG_WARNING: PPL_LOG_WRITE(3, message, severity); break; // TRACE_LEVEL_WARNING
    case LOG_DEBUG:   PPL_LOG_WRITE(5, message, severity); break; // TRACE_LEVEL_VERBOSE
    default:          PPL_LOG_WRITE(4, message, severity); break; // TRACE_LEVEL_INFORMATION
    }
}


BOOL PplLogInit(void)
{
    // TraceLoggingRegister returns an HRESULT in userspace.
    HRESULT hr = TraceLoggingRegister(g_RedEdrPplLogProvider);
    if (FAILED(hr)) {
        // Fall back to OutputDebugString so a debugger still sees the failure.
        char msg[128];
        _snprintf_s(msg, sizeof(msg), _TRUNCATE,
                    "[RedEdr PPL] PplLogInit: TraceLoggingRegister failed 0x%08X\n", hr);
        OutputDebugStringA(msg);
        return FALSE;
    }
    return TRUE;
}


void PplLogUninit(void)
{
    TraceLoggingUnregister(g_RedEdrPplLogProvider);
}


void LOG_A(int verbosity, const char* format, ...)
{
    char message[DATA_BUFFER_SIZE];

    va_list arg_ptr;
    va_start(arg_ptr, format);
    vsnprintf_s(message, sizeof(message), _TRUNCATE, format, arg_ptr);
    va_end(arg_ptr);

    LogEtwEvent(verbosity, message);
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    WCHAR wide_message[DATA_BUFFER_SIZE];

    va_list arg_ptr;
    va_start(arg_ptr, format);
    vswprintf_s(wide_message, sizeof(wide_message) / sizeof(wchar_t), format, arg_ptr);
    va_end(arg_ptr);

    // Convert wide string to UTF-8 for the ANSI-string ETW field.
    char message[DATA_BUFFER_SIZE];
    int result = WideCharToMultiByte(CP_UTF8, 0, wide_message, -1, message, sizeof(message), NULL, NULL);
    if (result > 0) {
        LogEtwEvent(verbosity, message);
    }
}
