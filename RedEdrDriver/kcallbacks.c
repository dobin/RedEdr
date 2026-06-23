#include <Ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#include "upipe.h"
#include "kapcinjector.h"
#include "kcallbacks.h"
#include "hashcache.h"
#include "settings.h"
#include "utils.h"
#include "../Shared/common.h"

// ZwSetInformationProcess is exported by ntoskrnl but not declared in WDK headers.
// Resolved dynamically via MmGetSystemRoutineAddress to avoid VCR001 analyzer warnings.
// ProcessLoggingInformation (class 87) sets per-process ETW-TI logging flags so that
// the Microsoft-Windows-Threat-Intelligence provider emits the full range of events
// (WriteVM, ReadVM, SetContextThread, SuspendThread, etc.) for this process.
// Reference: https://fluxsec.red/reverse-engineering-windows-11-kernel
typedef NTSTATUS (NTAPI *PFN_ZwSetInformationProcess)(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength
);
static PFN_ZwSetInformationProcess g_ZwSetInformationProcess = NULL;

typedef NTSTATUS (NTAPI *PFN_ZwQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG  ProcessInformationClass,
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength
);
static PFN_ZwQueryInformationProcess g_ZwQueryInformationProcess = NULL;

typedef NTSTATUS (NTAPI *PFN_ZwQuerySystemInformation)(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);
static PFN_ZwQuerySystemInformation g_ZwQuerySystemInformation = NULL;

// PsGetProcessSignatureLevel / PsGetProcessSectionSignatureLevel
// These documented kernel APIs return the SignatureLevel and
// SectionSignatureLevel EPROCESS fields without needing the raw offset.
// Available since Windows 8.1; resolved dynamically to stay compatible.
typedef UCHAR (NTAPI *PFN_PsGetProcessSignatureLevel)(
    PEPROCESS Process
);
static PFN_PsGetProcessSignatureLevel g_PsGetProcessSignatureLevel = NULL;

typedef UCHAR (NTAPI *PFN_PsGetProcessSectionSignatureLevel)(
    PEPROCESS Process
);
static PFN_PsGetProcessSectionSignatureLevel g_PsGetProcessSectionSignatureLevel = NULL;

// PROCESS_LOGGING_INFORMATION
// based on https://www.legacyy.xyz/defenseevasion/windows/2024/04/24/disabling-etw-ti-without-ppl.html
#define ProcessLoggingInformation 96  // 0x60  

typedef union _PROCESS_LOGGING_INFORMATION {
    ULONG Flags;
    struct _PROCESS_LOGGING_INFORMATION_BITS {
        ULONG EnableReadVmLogging              : 1;
        ULONG EnableWriteVmLogging             : 1;
        ULONG EnableProcessSuspendResumeLogging: 1;
        ULONG EnableThreadSuspendResumeLogging : 1;
        ULONG EnableLocalExecProtectVmLogging  : 1;
        ULONG EnableRemoteExecProtectVmLogging : 1;
        ULONG EnableImpersonationLogging       : 1;
        ULONG Reserved                         : 25;
    } Bits;
} PROCESS_LOGGING_INFORMATION;

// Enable all ETW-TI logging flags for the given process.
// Must be called at PASSIVE_LEVEL (process-creation callbacks run at PASSIVE_LEVEL).
// Returns TRUE on success, FALSE on failure.
static BOOLEAN EnableProcessTelemetryLogging(PEPROCESS Process) {
    HANDLE hProcess = NULL;
    NTSTATUS status;
    BOOLEAN success = FALSE;

    // Convert EPROCESS pointer to a kernel HANDLE without a separate ZwOpenProcess.
    status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_ALL_ACCESS,
        *PsProcessType,
        KernelMode,
        &hProcess
    );
    if (!NT_SUCCESS(status)) {
        LOG_A(LOG_WARNING, "EnableProcessTelemetryLogging: ObOpenObjectByPointer failed: 0x%08X", status);
        return FALSE;
    }

    // Set the desired logging flags for this process. We enable all the ETW-TI flags to get the full range of events.
    PROCESS_LOGGING_INFORMATION processLoggingInfo = { 0 };
    processLoggingInfo.Bits.EnableReadVmLogging = 1;
    processLoggingInfo.Bits.EnableWriteVmLogging = 1;
    processLoggingInfo.Bits.EnableProcessSuspendResumeLogging = 1;
    processLoggingInfo.Bits.EnableThreadSuspendResumeLogging = 1;
    // Win11 only (build >= 22000); these bits are not present on Win10
    RTL_OSVERSIONINFOW osVer = {0};
    osVer.dwOSVersionInfoSize = sizeof(osVer);
    if (NT_SUCCESS(RtlGetVersion(&osVer)) && osVer.dwBuildNumber >= 22000) {
        LOG_A(LOG_INFO, "Detected Windows 11");
        processLoggingInfo.Bits.EnableLocalExecProtectVmLogging = 1;
        processLoggingInfo.Bits.EnableRemoteExecProtectVmLogging = 1;
        //processLoggingInfo.Bits.EnableImpersonationLogging = 1;
    }
    // Dont touch reserved for now
    //processLoggingInfo.Bits.Reserved = 0;

    if (g_ZwSetInformationProcess == NULL) {
        ZwClose(hProcess);
        return FALSE;
    }
    status = g_ZwSetInformationProcess(
        hProcess,
        ProcessLoggingInformation,
        &processLoggingInfo,
        sizeof(processLoggingInfo)
    );
    if (!NT_SUCCESS(status)) {
        LOG_A(LOG_WARNING, "EnableProcessTelemetryLogging: ZwSetInformationProcess failed: 0x%08X", status);
        success = FALSE;
    } else {
        success = TRUE;
    }

    ZwClose(hProcess);
    return success;
}

// Query and debug-log the current PROCESS_LOGGING_INFORMATION flags for a process.
static void LogProcessTelemetryLoggingFlags(PEPROCESS Process, HANDLE pid) {
    HANDLE hProcess = NULL;
    NTSTATUS status;

    status = ObOpenObjectByPointer(
        Process,
        OBJ_KERNEL_HANDLE,
        NULL,
        PROCESS_ALL_ACCESS,
        *PsProcessType,
        KernelMode,
        &hProcess
    );
    if (!NT_SUCCESS(status)) {
        LOG_A(LOG_INFO, "LogProcessTelemetryLoggingFlags: ObOpenObjectByPointer failed for pid %llu: 0x%08X", (ULONG64)pid, status);
        return;
    }

    if (g_ZwQueryInformationProcess == NULL) {
        ZwClose(hProcess);
        return;
    }

    PROCESS_LOGGING_INFORMATION loggingInfo = { 0 };
    ULONG returnLength = 0;
    status = g_ZwQueryInformationProcess(
        hProcess,
        ProcessLoggingInformation,
        &loggingInfo,
        sizeof(loggingInfo),
        &returnLength
    );
    ZwClose(hProcess);

    if (!NT_SUCCESS(status)) {
        LOG_A(LOG_INFO, "LogProcessTelemetryLoggingFlags: ZwQueryInformationProcess failed for pid %llu: 0x%08X", (ULONG64)pid, status);
        return;
    }

    LOG_A(LOG_INFO, "pid %llu ETW-TI flags=0x%02X: ReadVM=%d WriteVM=%d ProcSuspRes=%d ThrSuspRes=%d LocalExecProt=%d RemoteExecProt=%d Impersonation=%d reserved=0x%02X",
        (ULONG64)pid,
        loggingInfo.Flags,
        loggingInfo.Bits.EnableReadVmLogging,
        loggingInfo.Bits.EnableWriteVmLogging,
        loggingInfo.Bits.EnableProcessSuspendResumeLogging,
        loggingInfo.Bits.EnableThreadSuspendResumeLogging,
        loggingInfo.Bits.EnableLocalExecProtectVmLogging,
        loggingInfo.Bits.EnableRemoteExecProtectVmLogging,
        loggingInfo.Bits.EnableImpersonationLogging,
        loggingInfo.Bits.Reserved);
}


// Enumerate all running processes and call EnableProcessTelemetryLogging for
// every process whose image name matches targetName (case-insensitive).
// Uses ZwQuerySystemInformation(SystemProcessInformation) to walk the live
// process list without relying on the driver's own hash table, so it works
// even for processes that were already running before the driver loaded.
VOID EnableTelemetryLoggingForProcessByName(PCWSTR targetName) {
#define SystemProcessInformation 5
    typedef struct _SYSTEM_PROCESS_INFORMATION {
        ULONG           NextEntryOffset;
        ULONG           NumberOfThreads;
        LARGE_INTEGER   Reserved[3];
        LARGE_INTEGER   CreateTime;
        LARGE_INTEGER   UserTime;
        LARGE_INTEGER   KernelTime;
        UNICODE_STRING  ImageName;
        KPRIORITY       BasePriority;
        HANDLE          UniqueProcessId;
        HANDLE          InheritedFromUniqueProcessId;
        ULONG           HandleCount;
        ULONG           SessionId;
        ULONG_PTR       PageDirectoryBase;
        SIZE_T          PeakVirtualSize;
        SIZE_T          VirtualSize;
        ULONG           PageFaultCount;
        SIZE_T          PeakWorkingSetSize;
        SIZE_T          WorkingSetSize;
        SIZE_T          QuotaPeakPagedPoolUsage;
        SIZE_T          QuotaPagedPoolUsage;
        SIZE_T          QuotaPeakNonPagedPoolUsage;
        SIZE_T          QuotaNonPagedPoolUsage;
        SIZE_T          PagefileUsage;
        SIZE_T          PeakPagefileUsage;
        SIZE_T          PrivatePageCount;
        LARGE_INTEGER   ReadOperationCount;
        LARGE_INTEGER   WriteOperationCount;
        LARGE_INTEGER   OtherOperationCount;
        LARGE_INTEGER   ReadTransferCount;
        LARGE_INTEGER   WriteTransferCount;
        LARGE_INTEGER   OtherTransferCount;
    } SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

    ULONG bufferSize = 1024 * 1024; // 1 MB initial allocation
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'PrEn');
    if (buffer == NULL) {
        LOG_A(LOG_WARNING, "EnableTelemetryLoggingForProcessByName: allocation failed");
        return;
    }

    if (g_ZwQuerySystemInformation == NULL) {
        LOG_A(LOG_WARNING, "EnableTelemetryLoggingForProcessByName: ZwQuerySystemInformation not resolved");
        ExFreePool(buffer);
        return;
    }
    ULONG returnLength = 0;
    NTSTATUS status = g_ZwQuerySystemInformation(
        SystemProcessInformation,
        buffer,
        bufferSize,
        &returnLength
    );
    if (!NT_SUCCESS(status)) {
        LOG_A(LOG_WARNING, "EnableTelemetryLoggingForProcessByName: ZwQuerySystemInformation failed 0x%08X", status);
        ExFreePool(buffer);
        return;
    }

    PSYSTEM_PROCESS_INFORMATION entry = (PSYSTEM_PROCESS_INFORMATION)buffer;
    for (;;) {
        // ImageName.Buffer may be NULL for the idle/system processes
        if (entry->ImageName.Buffer != NULL && entry->ImageName.Length > 0) {
            UNICODE_STRING targetUs;
            RtlInitUnicodeString(&targetUs, targetName);
            if (RtlEqualUnicodeString(&entry->ImageName, &targetUs, TRUE)) {
                HANDLE pid = entry->UniqueProcessId;
                PEPROCESS process = NULL;
                status = PsLookupProcessByProcessId(pid, &process);
                if (NT_SUCCESS(status)) {
                    BOOLEAN ok = EnableProcessTelemetryLogging(process);
                    LOG_A(LOG_INFO, "EnableTelemetryLoggingForProcessByName: pid %llu -> %d",
                        (ULONG64)pid, ok);
                    ObDereferenceObject(process);
                } else {
                    LOG_A(LOG_WARNING, "EnableTelemetryLoggingForProcessByName: PsLookupProcessByProcessId pid %llu failed 0x%08X",
                        (ULONG64)pid, status);
                }
            }
        }

        if (entry->NextEntryOffset == 0) {
            break;
        }
        entry = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)entry + entry->NextEntryOffset);
    }

    ExFreePool(buffer);
}


int InitCallbacks() {
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"ZwSetInformationProcess");
    g_ZwSetInformationProcess = (PFN_ZwSetInformationProcess)MmGetSystemRoutineAddress(&funcName);
    if (g_ZwSetInformationProcess == NULL) {
        LOG_A(LOG_WARNING, "InitCallbacks: failed to resolve ZwSetInformationProcess");
    }

    RtlInitUnicodeString(&funcName, L"ZwQueryInformationProcess");
    g_ZwQueryInformationProcess = (PFN_ZwQueryInformationProcess)MmGetSystemRoutineAddress(&funcName);
    if (g_ZwQueryInformationProcess == NULL) {
        LOG_A(LOG_WARNING, "InitCallbacks: failed to resolve ZwQueryInformationProcess");
    }

    RtlInitUnicodeString(&funcName, L"ZwQuerySystemInformation");
    g_ZwQuerySystemInformation = (PFN_ZwQuerySystemInformation)MmGetSystemRoutineAddress(&funcName);
    if (g_ZwQuerySystemInformation == NULL) {
        LOG_A(LOG_WARNING, "InitCallbacks: failed to resolve ZwQuerySystemInformation");
    }

    RtlInitUnicodeString(&funcName, L"PsGetProcessSignatureLevel");
    g_PsGetProcessSignatureLevel = (PFN_PsGetProcessSignatureLevel)MmGetSystemRoutineAddress(&funcName);
    if (g_PsGetProcessSignatureLevel == NULL) {
        LOG_A(LOG_WARNING, "InitCallbacks: failed to resolve PsGetProcessSignatureLevel");
    }

    RtlInitUnicodeString(&funcName, L"PsGetProcessSectionSignatureLevel");
    g_PsGetProcessSectionSignatureLevel = (PFN_PsGetProcessSectionSignatureLevel)MmGetSystemRoutineAddress(&funcName);
    if (g_PsGetProcessSectionSignatureLevel == NULL) {
        LOG_A(LOG_WARNING, "InitCallbacks: failed to resolve PsGetProcessSectionSignatureLevel");
    }
    return TRUE;
}

void UninitCallbacks() {
}


// For: PsSetCreateProcessNotifyRoutineEx()
void CreateProcessNotifyRoutine(PEPROCESS process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo) {
    // Still execute even if we are globally disabled, but need kapc injection
    if (!g_Settings.enable_logging && !g_Settings.enable_kapc_injection) {
        return;
    }
    if (createInfo == NULL) {
        // process is exiting
        return;
    }
    createInfo->CreationStatus = STATUS_SUCCESS;

    ULONG64 systemTime;
    KeQuerySystemTime(&systemTime);

    PPROCESS_INFO processInfo = LookupProcessInfo(pid);
    if (processInfo == NULL) {
        PUNICODE_STRING processName = NULL;
        PUNICODE_STRING parent_processName = NULL;

        SeLocateProcessImageName(process, &processName);

        PEPROCESS parent_process = NULL;
        if (NT_SUCCESS(PsLookupProcessByProcessId(createInfo->ParentProcessId, &parent_process))) {
            SeLocateProcessImageName(parent_process, &parent_processName);
        }

        //LOG_A(LOG_INFO, "Process %wZ created", processName);
        //LOG_A(LOG_INFO, "            PID: %d", pid);
        //LOG_A(LOG_INFO, "            Created by: %wZ", parent_processName);
        //LOG_A(LOG_INFO, "            ImageBase: %ws", createInfo->ImageFileName->Buffer);

        POBJECT_NAME_INFORMATION objFileDosDeviceName;
        IoQueryFileDosDeviceName(createInfo->FileObject, &objFileDosDeviceName);
        //LOG_A(LOG_INFO, "            DOS path: %ws", objFileDosDeviceName->Name.Buffer);
        //LOG_A(LOG_INFO, "            CommandLine: %ws", createInfo->CommandLine->Buffer);

        processInfo = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(PROCESS_INFO), 'Proc');
        if (!processInfo) {
            if (processName) ExFreePool(processName);
            if (parent_processName) ExFreePool(parent_processName);
            if (parent_process) ObDereferenceObject(parent_process);
            return;
        }

        processInfo->ProcessId = pid;
        Unicodestring2wcharAlloc(processName, processInfo->name, PROC_NAME_LEN);
        processInfo->ppid = createInfo->ParentProcessId;
        Unicodestring2wcharAlloc(parent_processName, processInfo->parent_name, PROC_NAME_LEN);
        processInfo->observe = 0;

        // Search in the unicode atm
        if (wcslen(g_Settings.target) > 0) {
            if (IsSubstringInUnicodeString(processName, g_Settings.target)) {
                processInfo->observe = 1;
                g_Settings.trace_pid = pid;
            }
        }
        // Check for children
        // TODO support grandchildren?
        // TODO use the other pid/ppid to make it more robust against PPID spoofing?
        if (g_Settings.trace_children && processInfo->ppid == g_Settings.trace_pid) {
            processInfo->observe = 1;
        }
        //LOG_A(LOG_INFO, "CreateProcessNotify: Process %d created, observe: %i", 
        //    pid, processInfo->observe);

        AddProcessInfo(pid, processInfo);

        // Release kernel object references and pool allocations from SeLocateProcessImageName
        if (processName) ExFreePool(processName);
        if (parent_processName) ExFreePool(parent_processName);
        if (parent_process) ObDereferenceObject(parent_process);
    }

    if (g_Settings.enable_logging && processInfo->observe) {
        char processName[PROC_NAME_LEN];
        char parentName[PROC_NAME_LEN];
        char ProcessLine[DATA_BUFFER_SIZE];

        NTSTATUS status;
        status = WcharToAscii(processInfo->name, wcslen(processInfo->name), processName, sizeof(processName));
        status = WcharToAscii(processInfo->parent_name, wcslen(processInfo->parent_name), parentName, sizeof(parentName));
        JsonEscape(processName, PROC_NAME_LEN);
        JsonEscape(parentName, PROC_NAME_LEN);

        RtlStringCbPrintfA(ProcessLine, DATA_BUFFER_SIZE, "{\"type\":\"kernel\",\"time\":%llu,\"func\":\"process_create\",\"krn_pid\":%llu,\"pid\":%llu,\"name\":\"%s\",\"ppid\":%llu,\"parent_name\":\"%s\"}",
            systemTime,
            (unsigned __int64)PsGetCurrentProcessId(),
            (unsigned __int64)pid, 
            processName,
            (unsigned __int64)createInfo->ParentProcessId, 
            parentName);
        LogEvent(ProcessLine);

        // Log current ETW-TI flags before modifying them.
        LogProcessTelemetryLoggingFlags(process, pid);

        // Enable all ETW-TI logging flags so Microsoft-Windows-Threat-Intelligence
        // emits the full range of events (ReadVM, WriteVM, SetContextThread, etc.)
        // for this process. Applied to all new processes; RedEdrPplService filters
        // by observe flag. Must run at PASSIVE_LEVEL - process callbacks qualify.
        if (g_Settings.enable_etwti_events) {
            BOOLEAN etwtiEnabledSuccess = EnableProcessTelemetryLogging(process);
            LOG_A(LOG_INFO, "Enabled ETW-TI logging for pid %d: %d", pid, etwtiEnabledSuccess);
        }

        // Log ETW-TI flags after modification to confirm they were set correctly.
        LogProcessTelemetryLoggingFlags(process, pid);
    }
}


// For: PsSetCreateThreadNotifyRoutine()
void CreateThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    if (!g_Settings.enable_logging) {
        return;
    }
    PROCESS_INFO* procInfo = LookupProcessInfo(ProcessId);
    if (procInfo == NULL || !procInfo->observe) {
        return;
    }

    ULONG64 systemTime;
    KeQuerySystemTime(&systemTime);

    char ThreadLine[DATA_BUFFER_SIZE];
    RtlStringCbPrintfA(ThreadLine, DATA_BUFFER_SIZE, "{\"type\":\"kernel\",\"time\":%llu,\"func\":\"thread_create\",\"krn_pid\":%llu,\"pid\":%llu,\"threadid\":%llu,\"create\":%d}",
        systemTime,
        (unsigned __int64)PsGetCurrentProcessId(),
        (unsigned __int64)ProcessId,
        (unsigned __int64)ThreadId,
        Create);
    LogEvent(ThreadLine);
}


// For: PsSetLoadImageNotifyRoutine
void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    UNREFERENCED_PARAMETER(ImageInfo);

    // Still execute even if we are globally disabled, but need kapc injection
    if (!g_Settings.enable_logging && !g_Settings.enable_kapc_injection) {
        return;
    }
    if (FullImageName == NULL) {
        return;
    }

    ULONG64 systemTime;
    KeQuerySystemTime(&systemTime);
    wchar_t ImageName[PATH_LEN] = { 0 };
    char AsciiImageName[PATH_LEN] = { 0 };

    // We may only have KAPC injection, and no logging
    if (g_Settings.enable_logging) {
        PROCESS_INFO* procInfo = LookupProcessInfo(ProcessId);
        if (procInfo != NULL && procInfo->observe) {
            Unicodestring2wcharAlloc(FullImageName, ImageName, PATH_LEN);
            WcharToAscii(ImageName, sizeof(ImageName), AsciiImageName, sizeof(AsciiImageName));
            JsonEscape(AsciiImageName, sizeof(AsciiImageName));
            char ImageLine[DATA_BUFFER_SIZE];
            RtlStringCbPrintfA(ImageLine, DATA_BUFFER_SIZE, "{\"type\":\"kernel\",\"time\":%llu,\"func\":\"image_load\",\"krn_pid\":%llu,\"pid\":%llu,\"image\":\"%s\"}",
                systemTime,
                (unsigned __int64)PsGetCurrentProcessId(),
                (unsigned __int64)ProcessId,
               AsciiImageName
            );
            LogEvent(ImageLine);
        }
    }
    if (g_Settings.enable_kapc_injection) {
        PPROCESS_INFO processInfo = LookupProcessInfo(ProcessId);
        if (processInfo != NULL && processInfo->observe) {
            // Atomically claim injection: only the first thread to succeed injects.
            if (InterlockedCompareExchange(&processInfo->injected, 1, 0) == 0) {
                int result = KapcInjectDll(FullImageName, ProcessId, ImageInfo);
                if (result) {
                    LOG_A(LOG_INFO, "Injected DLL into pid: %d", ProcessId);
                } else {
                    // Reset so injection can be retried on the next image load.
                    InterlockedExchange(&processInfo->injected, 0);
                }
            }
        }
    }
}


// For: ObRegisterCallbacks

typedef struct _TD_CALL_CONTEXT
{
    PTD_CALLBACK_REGISTRATION CallbackRegistration;

    OB_OPERATION Operation;
    PVOID Object;
    POBJECT_TYPE ObjectType;
}
TD_CALL_CONTEXT, * PTD_CALL_CONTEXT;

void TdSetCallContext(
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo,
    _In_ PTD_CALLBACK_REGISTRATION CallbackRegistration
)
{
    PTD_CALL_CONTEXT CallContext;

    CallContext = (PTD_CALL_CONTEXT)ExAllocatePool2(
        POOL_FLAG_PAGED, sizeof(TD_CALL_CONTEXT), TD_CALL_CONTEXT_TAG
    );

    if (CallContext == NULL)
    {
        return;
    }

    CallContext->CallbackRegistration = CallbackRegistration;
    CallContext->Operation = PreInfo->Operation;
    CallContext->Object = PreInfo->Object;
    CallContext->ObjectType = PreInfo->ObjectType;

    PreInfo->CallContext = CallContext;
}


#define CB_PROCESS_TERMINATE 0x0001
#define CB_THREAD_TERMINATE  0x0001

// Callback
OB_PREOP_CALLBACK_STATUS CBTdPreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION PreInfo
)
{
    // https://github.com/microsoft/Windows-driver-samples/blob/main/general/obcallback/driver/callback.c
    if (!g_Settings.enable_logging) {
        return OB_PREOP_SUCCESS;
    }

    PTD_CALLBACK_REGISTRATION CallbackRegistration;

    ACCESS_MASK AccessBitsToClear = 0;
    ACCESS_MASK AccessBitsToSet = 0;
    ACCESS_MASK InitialDesiredAccess = 0;
    ACCESS_MASK OriginalDesiredAccess = 0;


    PACCESS_MASK DesiredAccess = NULL;

    LPCWSTR ObjectTypeName = NULL;
    LPCWSTR OperationName = NULL;

    // Not using driver specific values at this time
    CallbackRegistration = (PTD_CALLBACK_REGISTRATION)RegistrationContext;


    // Only want to filter attempts to access protected process
    // all other processes are left untouched

    if (PreInfo->ObjectType == *PsProcessType) {
        //
        // Ignore requests for processes other than our target process.
        //

        // if (TdProtectedTargetProcess != NULL &&
        //    TdProtectedTargetProcess != PreInfo->Object)
        /*if (TdProtectedTargetProcess != PreInfo->Object)
        {
            goto Exit;
        }*/

        //
        // Also ignore requests that are trying to open/duplicate the current
        // process.
        //

        if (PreInfo->Object == PsGetCurrentProcess()) {
            LOG_A(LOG_DEBUG, "CBTdPreOperationCallback: ignore process open/duplicate from the protected process itself");
            goto Exit;
        }

        ObjectTypeName = L"PsProcessType";
        AccessBitsToClear = CB_PROCESS_TERMINATE;
        AccessBitsToSet = 0;
    }
    else if (PreInfo->ObjectType == *PsThreadType) {
        HANDLE ProcessIdOfTargetThread = PsGetThreadProcessId((PETHREAD)PreInfo->Object);

        //
        // Ignore requests for threads belonging to processes other than our
        // target process.
        //

        // if (CallbackRegistration->TargetProcess   != NULL &&
        //     CallbackRegistration->TargetProcessId != ProcessIdOfTargetThread)
        /*if (TdProtectedTargetProcessId != ProcessIdOfTargetThread) {
            goto Exit;
        }*/

        //
        // Also ignore requests for threads belonging to the current processes.
        //

        if (ProcessIdOfTargetThread == PsGetCurrentProcessId()) {
            LOG_A(LOG_DEBUG, "CBTdPreOperationCallback: ignore thread open/duplicate from the protected process itself");
            goto Exit;
        }

        ObjectTypeName = L"PsThreadType";
        AccessBitsToClear = CB_THREAD_TERMINATE;
        AccessBitsToSet = 0;
    }
    else {
        LOG_A(LOG_ERROR, "CBTdPreOperationCallback: unexpected object type");
        goto Exit;
    }

    switch (PreInfo->Operation) {
    case OB_OPERATION_HANDLE_CREATE:
        DesiredAccess = &PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
        OriginalDesiredAccess = PreInfo->Parameters->CreateHandleInformation.OriginalDesiredAccess;

        OperationName = L"OB_OPERATION_HANDLE_CREATE";
        break;

    case OB_OPERATION_HANDLE_DUPLICATE:
        DesiredAccess = &PreInfo->Parameters->DuplicateHandleInformation.DesiredAccess;
        OriginalDesiredAccess = PreInfo->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;

        OperationName = L"OB_OPERATION_HANDLE_DUPLICATE";
        break;

    default:
        break;
    }

    InitialDesiredAccess = *DesiredAccess;

    // Filter only if request made outside of the kernel
    if (PreInfo->KernelHandle != 1) {
        *DesiredAccess &= ~AccessBitsToClear;
        *DesiredAccess |= AccessBitsToSet;
    }

    //
    // Set call context.
    //
    // TODO necessary?
    TdSetCallContext(PreInfo, CallbackRegistration);


    /*DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: CBTdPreOperationCallback: PROTECTED process %p (ID 0x%p)",
        TdProtectedTargetProcess,
        (PVOID)TdProtectedTargetProcessId
    );*/

    if (1) {
        char line[DATA_BUFFER_SIZE] = { 0 };
        RtlStringCbPrintfA(line, DATA_BUFFER_SIZE, "%p:%p;%p;%ls;%ls;%d,0x%x,0x%x,0x%x",
            /*"ObCallbackTest: CBTdPreOperationCallback"
            "    Client Id:    %p:%p"
            "    Object:       %p"
            "    Type:         %ls"
            "    Operation:    %ls (KernelHandle=%d)"
            "    OriginalDesiredAccess: 0x%x"
            "    DesiredAccess (in):    0x%x"
            "    DesiredAccess (out):   0x%x",*/
            PsGetCurrentProcessId(),
            PsGetCurrentThreadId(),
            PreInfo->Object,
            ObjectTypeName,
            OperationName,
            PreInfo->KernelHandle,
            OriginalDesiredAccess,
            InitialDesiredAccess,
            *DesiredAccess);
        LogEvent(line);
    } else {
        LOG_A(LOG_ERROR,
            "CBTdPreOperationCallback"
            "    Client Id:    %p:%p"
            "    Object:       %p"
            "    Type:         %ls"
            "    Operation:    %ls (KernelHandle=%d)"
            "    OriginalDesiredAccess: 0x%x"
            "    DesiredAccess (in):    0x%x"
            "    DesiredAccess (out):   0x%x",
            PsGetCurrentProcessId(),
            PsGetCurrentThreadId(),
            PreInfo->Object,
            ObjectTypeName,
            OperationName,
            PreInfo->KernelHandle,
            OriginalDesiredAccess,
            InitialDesiredAccess,
            *DesiredAccess
        );
    }

Exit:
    return OB_PREOP_SUCCESS;
}


//////////////////////////////////////////////////////////////////////
// Process Protection Level Manipulation (DKOM)
//
// Modifies the PS_PROTECTION field in the EPROCESS structure of a 
// target process. This allows elevating a PPL-Antimalware process 
// (e.g. RedEdrPplService) to PPL-WinTcb so it can access higher-
// protected processes like MsSense.exe.
//
// Inspired by: https://github.com/hfiref0x/KDU (ps.cpp)
//////////////////////////////////////////////////////////////////////

// PS_PROTECTION offsets in EPROCESS for different Windows builds.
// These are well-known offsets from Windows internals / KDU.
#define PSPROTECTION_OFFSET_9600   0x67A   // Win8.1
#define PSPROTECTION_OFFSET_10240  0x6AA   // Win10 TH1
#define PSPROTECTION_OFFSET_10586  0x6B2   // Win10 TH2
#define PSPROTECTION_OFFSET_14393  0x6C2   // Win10 RS1
#define PSPROTECTION_OFFSET_15063  0x6CA   // Win10 RS2..RS4 (15063,16299,17134,17763)
#define PSPROTECTION_OFFSET_18362  0x6FA   // Win10 19H1/19H2
#define PSPROTECTION_OFFSET_19041  0x87A   // Win10 20H1..22H2, Win11 21H2..23H2
#define PSPROTECTION_OFFSET_26100  0x5FA   // Win11 24H2..25H2

// PS_PROTECTION structure layout (1 byte in EPROCESS):
//   Bits [2:0]  = Type   (PS_PROTECTED_TYPE)
//   Bit  [3]    = Audit
//   Bits [7:4]  = Signer (PS_PROTECTED_SIGNER)
#define MAKE_PS_PROTECTION(signer, audit, type) \
    (UCHAR)(((signer) << 4) | (((audit) & 1) << 3) | ((type) & 0x7))


// Get the PS_PROTECTION offset for the current OS build number.
static ULONG_PTR GetHardcodedPsProtectionOffset(ULONG buildNumber) {
    // Map build numbers to known offsets
    if (buildNumber >= 26100) {
        return PSPROTECTION_OFFSET_26100;  // Win11 24H2+
    }
    else if (buildNumber >= 19041) {
        return PSPROTECTION_OFFSET_19041;  // Win10 20H1 through Win11 23H2
    }
    else if (buildNumber >= 18362) {
        return PSPROTECTION_OFFSET_18362;  // Win10 19H1/19H2
    }
    else if (buildNumber >= 15063) {
        return PSPROTECTION_OFFSET_15063;  // Win10 RS2..RS4
    }
    else if (buildNumber >= 14393) {
        return PSPROTECTION_OFFSET_14393;  // Win10 RS1
    }
    else if (buildNumber >= 10586) {
        return PSPROTECTION_OFFSET_10586;  // Win10 TH2
    }
    else if (buildNumber >= 10240) {
        return PSPROTECTION_OFFSET_10240;  // Win10 TH1
    }
    else if (buildNumber >= 9600) {
        return PSPROTECTION_OFFSET_9600;   // Win8.1
    }
    return 0; // Unknown/unsupported
}


// Scan the EPROCESS structure for the PS_PROTECTION field by looking for the
// well-known layout pattern:
//
//   [SignatureLevel] [SectionSignatureLevel] [Protection] [HangCount/GhostCount bitfield]
//     offset-2          offset-1               offset       offset+1
//
// This is a stable structural invariant across all known Windows builds (8.1+).
// SignatureLevel and SectionSignatureLevel are non-zero UCHARs for protected
// processes, with values in the range 0x01..0x3F (code integrity signature
// levels). By matching the 3-byte pattern [nonzero-siglevel, nonzero-secsiglevel,
// expected-protection], we dramatically reduce false positives compared to
// scanning for a single byte value.
//
// Parameters:
//   Process             - PEPROCESS pointer for the target process
//   ExpectedProtection  - The PS_PROTECTION byte value we expect to find
//                         (e.g. MAKE_PS_PROTECTION(ANTIMALWARE, 0, PROTECTED_LIGHT) = 0x31)
//   ScanRangeBytes      - How many bytes of EPROCESS to scan (e.g. 4096)
//
// Returns: the offset of the Protection field if exactly one candidate is found,
//          or 0 if zero or multiple candidates are found.
static ULONG_PTR ScanEprocessForProtectionOffset(
    PEPROCESS Process,
    UCHAR ExpectedProtection,
    ULONG ScanRangeBytes)
{
    ULONG candidateCount = 0;
    ULONG_PTR candidateOffset = 0;
    ULONG knownOffset = 0;

    // Get the hardcoded offset for comparison / logging
    RTL_OSVERSIONINFOW osVer = { 0 };
    osVer.dwOSVersionInfoSize = sizeof(osVer);
    if (NT_SUCCESS(RtlGetVersion(&osVer))) {
        knownOffset = (ULONG)GetHardcodedPsProtectionOffset(osVer.dwBuildNumber);
    }

    // Query the ACTUAL signature level values from the kernel without needing
    // to know EPROCESS offsets. These APIs are available since Windows 8.1.
    UCHAR expectedSigLevel = 0;
    UCHAR expectedSecSigLevel = 0;
    BOOLEAN haveExpectedSigLevels = FALSE;

    if (g_PsGetProcessSignatureLevel != NULL && g_PsGetProcessSectionSignatureLevel != NULL) {
        expectedSigLevel    = g_PsGetProcessSignatureLevel(Process);
        expectedSecSigLevel = g_PsGetProcessSectionSignatureLevel(Process);
        haveExpectedSigLevels = TRUE;
        LOG_A(LOG_INFO, "ScanEprocessForProtectionOffset: kernel APIs report "
            "SignatureLevel=0x%02X SectionSignatureLevel=0x%02X",
            expectedSigLevel, expectedSecSigLevel);
    } else {
        LOG_A(LOG_WARNING, "ScanEprocessForProtectionOffset: "
            "PsGetProcessSignatureLevel not available, falling back to heuristics");
    }

    LOG_A(LOG_INFO, "ScanEprocessForProtectionOffset: EPROCESS=%p, expected=0x%02X, range=%lu, knownOffset=0x%lX",
        Process, ExpectedProtection, ScanRangeBytes, knownOffset);

    // We need at least 2 bytes before the candidate for SignatureLevel and
    // SectionSignatureLevel, so start scanning at offset 2.
    // Scan at 1-byte granularity since PS_PROTECTION is not necessarily aligned
    // (e.g. 0x87A on build 22631).
    for (ULONG offset = 2; offset < ScanRangeBytes; offset += 1) {
        __try {
            UCHAR* base = (UCHAR*)((ULONG_PTR)Process + offset);
            UCHAR val = *base;

            if (val != ExpectedProtection) {
                continue;
            }

            UCHAR sigLevel    = *(base - 2);  // SignatureLevel
            UCHAR secSigLevel = *(base - 1);  // SectionSignatureLevel

            if (haveExpectedSigLevels) {
                // Exact match using values from the kernel APIs — no false positives.
                if (sigLevel != expectedSigLevel || secSigLevel != expectedSecSigLevel) {
                    continue;
                }
            } else {
                // Fallback heuristic: both must be non-zero and look like
                // signature level values (small, not part of a pointer).
                if (sigLevel == 0 || secSigLevel == 0) {
                    continue;
                }
                if (sigLevel > 0x7F || secSigLevel > 0x7F) {
                    continue;
                }
            }

            // We have a strong candidate!
            candidateCount++;
            candidateOffset = offset;
            BOOLEAN isKnownOffset = (offset == knownOffset);

            LOG_A(LOG_INFO, "ScanEprocessForProtectionOffset: CANDIDATE at offset 0x%04lX  "
                "SignatureLevel=0x%02X  SectionSignatureLevel=0x%02X  Protection=0x%02X  %s",
                offset, sigLevel, secSigLevel, val,
                isKnownOffset ? "<-- MATCHES KNOWN OFFSET" : "");

            // Log surrounding context bytes for manual verification.
            if (offset >= 8 && (offset + 8) < ScanRangeBytes) {
                UCHAR* ctx = (UCHAR*)((ULONG_PTR)Process + offset - 8);
                LOG_A(LOG_INFO, "  context[-8..+8]: "
                    "%02X %02X %02X %02X %02X %02X %02X %02X [%02X] %02X %02X %02X %02X %02X %02X %02X",
                    ctx[0], ctx[1], ctx[2], ctx[3], ctx[4], ctx[5], ctx[6], ctx[7],
                    ctx[8],  // this is our candidate (Protection byte)
                    ctx[9], ctx[10], ctx[11], ctx[12], ctx[13], ctx[14], ctx[15]);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            LOG_A(LOG_WARNING, "ScanEprocessForProtectionOffset: exception at offset 0x%04lX, stopping scan", offset);
            break;
        }
    }

    LOG_A(LOG_INFO, "ScanEprocessForProtectionOffset: found %lu candidate(s)", candidateCount);

    if (candidateCount == 1) {
        LOG_A(LOG_INFO, "ScanEprocessForProtectionOffset: exactly 1 candidate at 0x%04lX — high confidence",
            (ULONG)candidateOffset);
        if (candidateOffset != knownOffset && knownOffset != 0) {
            LOG_A(LOG_WARNING, "ScanEprocessForProtectionOffset: WARNING — scanned offset 0x%04lX differs from hardcoded 0x%04lX!",
                (ULONG)candidateOffset, knownOffset);
        }
        return candidateOffset;
    } else if (candidateCount == 0) {
        LOG_A(LOG_WARNING, "ScanEprocessForProtectionOffset: NO candidates found! "
            "Expected pattern [SigLevel, SecSigLevel, 0x%02X] not present in scanned range",
            ExpectedProtection);
    } else {
        LOG_A(LOG_WARNING, "ScanEprocessForProtectionOffset: %lu candidates — ambiguous, "
            "cannot auto-detect. Known offset 0x%lX",
            candidateCount, knownOffset);
    }

    return 0;
}


// Set the PS_PROTECTION field of a process identified by PID.
// This performs Direct Kernel Object Manipulation (DKOM) to change
// the protection level of a running process.
//
// Parameters:
//   ProcessId       - PID of the target process
//   ProtectionSigner - PS_PROTECTED_SIGNER_* value (e.g. 6 for WinTcb)
//   ProtectionType   - PS_PROTECTED_TYPE_* value (e.g. 1 for ProtectedLight)
//   ProtectionAudit  - Audit flag (usually 0)
//
// Returns NTSTATUS
NTSTATUS SetProcessProtection(
    ULONG ProcessId,
    UCHAR ProtectionSigner,
    UCHAR ProtectionType,
    UCHAR ProtectionAudit)
{
    NTSTATUS status = STATUS_SUCCESS;
    PEPROCESS process = NULL;
    ULONG_PTR protectionOffset = 0;

    LOG_A(LOG_INFO, "SetProcessProtection: pid=%lu signer=%u type=%u audit=%u",
        ProcessId, ProtectionSigner, ProtectionType, ProtectionAudit);

    // Get the OS build number to determine the EPROCESS offset
    RTL_OSVERSIONINFOW osVer = { 0 };
    osVer.dwOSVersionInfoSize = sizeof(osVer);
    status = RtlGetVersion(&osVer);
    if (!NT_SUCCESS(status)) {
        LOG_A(LOG_ERROR, "SetProcessProtection: RtlGetVersion failed: 0x%08X", status);
        return status;
    }

    LOG_A(LOG_INFO, "SetProcessProtection: OS build %lu", osVer.dwBuildNumber);

    protectionOffset = GetHardcodedPsProtectionOffset(osVer.dwBuildNumber);
    if (protectionOffset == 0) {
        LOG_A(LOG_WARNING, "SetProcessProtection: Unsupported OS build %lu, will attempt dynamic offset discovery", osVer.dwBuildNumber);
    } else {
        LOG_A(LOG_INFO, "SetProcessProtection: PS_PROTECTION offset = 0x%lX", (ULONG)protectionOffset);
    }

    // Look up the EPROCESS for the target PID
    status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        LOG_A(LOG_ERROR, "SetProcessProtection: PsLookupProcessByProcessId failed for pid %lu: 0x%08X",
            ProcessId, status);
        return status;
    }

    // The expected current protection byte: the process should currently be
    // running as PPL-Antimalware-Light (signer=3, audit=0, type=1 => 0x31).
    // We compute it from the *requested* new values' type/audit but with the
    // *known current* signer (Antimalware=3). However, we don't know the exact
    // current value without reading EPROCESS, so use the scan with the known
    // target value to locate the field, then read back the actual current byte.
    //
    // Strategy: if we have a hardcoded offset, use it and also run the scanner
    // for verification. If the build is unknown (offset == 0), derive the
    // expected Protection byte we'll be writing, use the scanner to find the
    // field, then use whatever the scanner finds at that location.
    UCHAR oldProtection = 0;
    UCHAR* pProtection = NULL;

    if (protectionOffset != 0) {
        // Known build: read current value via hardcoded offset.
        pProtection = (UCHAR*)((ULONG_PTR)process + protectionOffset);
        oldProtection = *pProtection;

        // Also run the scanner for logging/verification against the known offset.
        // We scan up to 0x1000 bytes (4KB) which covers all known EPROCESS layouts.
        ScanEprocessForProtectionOffset(process, oldProtection, 0x1000);
    } else {
        // Unknown build: we don't know the current protection value, so we cannot
        // directly pass it to the scanner. Instead, compute the new value we want
        // to write (caller-specified signer/type/audit) and scan for that — if the
        // process is already at the target level, the scan finds it. More robustly,
        // try scanning for each valid PPL-Light byte (signer 1..7, type=1, audit=0).
        // In practice, our PPL service starts as Antimalware-Light (0x31), so try that.
        UCHAR candidateProtections[] = {
            MAKE_PS_PROTECTION(PS_PROTECTED_SIGNER_ANTIMALWARE, 0, PS_PROTECTED_TYPE_PROTECTED_LIGHT), // 0x31
            MAKE_PS_PROTECTION(PS_PROTECTED_SIGNER_LSA,         0, PS_PROTECTED_TYPE_PROTECTED_LIGHT), // 0x41
            MAKE_PS_PROTECTION(PS_PROTECTED_SIGNER_WINDOWS,     0, PS_PROTECTED_TYPE_PROTECTED_LIGHT), // 0x51
            MAKE_PS_PROTECTION(PS_PROTECTED_SIGNER_WINTCB,      0, PS_PROTECTED_TYPE_PROTECTED_LIGHT), // 0x61
        };
        for (ULONG i = 0; i < ARRAYSIZE(candidateProtections); i++) {
            ULONG_PTR scannedOffset = ScanEprocessForProtectionOffset(process, candidateProtections[i], 0x1000);
            if (scannedOffset != 0) {
                protectionOffset = scannedOffset;
                pProtection = (UCHAR*)((ULONG_PTR)process + protectionOffset);
                oldProtection = *pProtection;
                LOG_A(LOG_INFO, "SetProcessProtection: dynamic discovery found offset 0x%lX (current=0x%02X)",
                    (ULONG)protectionOffset, oldProtection);
                break;
            }
        }
        if (pProtection == NULL) {
            LOG_A(LOG_ERROR, "SetProcessProtection: dynamic offset discovery failed for build %lu",
                osVer.dwBuildNumber);
            ObDereferenceObject(process);
            return STATUS_NOT_SUPPORTED;
        }
    }
    LOG_A(LOG_INFO, "SetProcessProtection: EPROCESS=%p, PS_PROTECTION at %p (offset=0x%lX)",
        process, pProtection, (ULONG)protectionOffset);
    LOG_A(LOG_INFO, "SetProcessProtection: Old protection = 0x%02X (Type=%u, Audit=%u, Signer=%u)",
        oldProtection,
        oldProtection & 0x7,           // Type
        (oldProtection >> 3) & 0x1,    // Audit
        (oldProtection >> 4) & 0xF);   // Signer

    // Write new protection value
    UCHAR newProtection = MAKE_PS_PROTECTION(ProtectionSigner, ProtectionAudit, ProtectionType);
    *pProtection = newProtection;

    // Verify the write
    UCHAR verifyProtection = *pProtection;
    LOG_A(LOG_INFO, "SetProcessProtection: New protection = 0x%02X (Type=%u, Audit=%u, Signer=%u)",
        verifyProtection,
        verifyProtection & 0x7,
        (verifyProtection >> 3) & 0x1,
        (verifyProtection >> 4) & 0xF);

    if (verifyProtection != newProtection) {
        LOG_A(LOG_ERROR, "SetProcessProtection: Verification failed! Expected 0x%02X, got 0x%02X",
            newProtection, verifyProtection);
        ObDereferenceObject(process);
        return STATUS_UNSUCCESSFUL;
    }

    LOG_A(LOG_INFO, "SetProcessProtection: Successfully changed protection for pid %lu", ProcessId);

    ObDereferenceObject(process);
    return STATUS_SUCCESS;
}

