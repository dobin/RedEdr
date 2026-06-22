#pragma once

//
// RedEdr Kernel-Log ETW Provider (TraceLogging)
//
// Modern ETW replacement for the legacy DbgPrintEx-based LOG_A. The provider
// emits one event per log call with the following shape:
//
//   Provider name : "RedEdr-Kernel-Log"
//   Provider GUID : 07a19134-15d7-4601-b106-4b7a7aafc582
//   Event name    : "Log"
//   Fields        : Message (ANSI string), Severity (UInt32)
//   Level         : mapped from LOG_* severity (see etwlog.c)
//
// Userspace consumers (e.g. a krabs-based reader in RedEdr.exe) can attach to
// the provider GUID above and filter on level / event name.
//

#include <Ntifs.h>
#include <TraceLoggingProvider.h>

//
// Declare the TraceLogging provider (extern). The actual definition
// (TRACELOGGING_DEFINE_PROVIDER) is in etwlog.c to avoid multiple definitions.
// The GUID is fixed and must never change after the first release, otherwise
// existing consumers break.
//
//   07a19134-15d7-4601-b106-4b7a7aafc582
//
TRACELOGGING_DECLARE_PROVIDER(g_RedEdrKernelLogProvider);

//
// Register the ETW provider. Must be called once during DriverEntry, before
// any LOG_A call. Returns STATUS_SUCCESS on success.
//
NTSTATUS EtwLogInit(void);

//
// Unregister the ETW provider. Must be called once during RedEdrUnload, as the
// very last action (after all LOG_A calls have completed).
//
void EtwLogUninit(void);

//
// Emit a single log event. Called by LOG_A in utils.c. The severity is one of
// the LOG_* constants from Shared/common.h and is mapped to an ETW level.
//
void LogEtwEvent(int severity, const char* message);
