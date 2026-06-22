#include <Ntifs.h>
#include <ntstrsafe.h>

#include "etwlog.h"
#include "../Shared/common.h"

//
// Define the TraceLogging provider (actual definition, not extern).
// This is the single definition; etwlog.h has only the DECLARE.
//
TRACELOGGING_DEFINE_PROVIDER(
    g_RedEdrKernelLogProvider,
    "RedEdr-Kernel-Log",
    (0x07a19134, 0x15d7, 0x4601, 0xb1, 0x06, 0x4b, 0x7a, 0x7a, 0xaf, 0xc5, 0x82));

//
// ETW level constants (WINEVENT_LEVEL_*).
//
// These are defined in user-mode <winmeta.h> / <evntprov.h> but do NOT exist
// in the kernel DDK headers, so we define them manually here. The numeric
// values are from the Windows ETW specification and are stable.
//
#define WINEVENT_LEVEL_ERROR    2
#define WINEVENT_LEVEL_WARNING  3
#define WINEVENT_LEVEL_INFO     4
#define WINEVENT_LEVEL_VERBOSE  5

//
// Severity -> ETW level mapping.
//
// LOG_* values come from Shared/common.h:
//   LOG_ERROR   0
//   LOG_WARNING 1
//   LOG_INFO    2
//   LOG_DEBUG   3
//
static UCHAR SeverityToEtwLevel(int severity)
{
    switch (severity) {
    case LOG_ERROR:   return WINEVENT_LEVEL_ERROR;
    case LOG_WARNING: return WINEVENT_LEVEL_WARNING;
    case LOG_INFO:    return WINEVENT_LEVEL_INFO;
    case LOG_DEBUG:   return WINEVENT_LEVEL_VERBOSE;
    default:          return WINEVENT_LEVEL_INFO;
    }
}


NTSTATUS EtwLogInit(void)
{
    NTSTATUS status = TraceLoggingRegister(g_RedEdrKernelLogProvider);
    if (!NT_SUCCESS(status)) {
        // Fall back to DbgPrintEx so a kernel debugger still sees the failure.
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "[RedEdr KRN] EtwLogInit: TraceLoggingRegister failed 0x%08X\n", status);
        return status;
    }
    return STATUS_SUCCESS;
}


void EtwLogUninit(void)
{
    TraceLoggingUnregister(g_RedEdrKernelLogProvider);
}


void LogEtwEvent(int severity, const char* message)
{
    if (message == NULL) {
        return;
    }

    UCHAR level = SeverityToEtwLevel(severity);

    //
    // Skip the formatting/emit cost when no consumer is listening at this
    // level. TraceLoggingProviderEnabled is cheap and avoids the event-write
    // path entirely for filtered-out levels.
    //
    if (!TraceLoggingProviderEnabled(g_RedEdrKernelLogProvider, level, 0)) {
        return;
    }

    TraceLoggingWrite(
        g_RedEdrKernelLogProvider,
        "Log",
        TraceLoggingString(message, "Message"),
        TraceLoggingUInt32((UINT32)severity, "Severity"));
}
