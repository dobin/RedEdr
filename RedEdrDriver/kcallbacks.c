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

// Class 87 - enables kernel-side ETW-TI logging bits in EPROCESS.
// Mirrors PROCESS_LOGGING_INFORMATION from ntpsapi.h (System Informer).
#define ProcessLoggingInformation 87

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
        LOG_A(LOG_WARNING, "[RedEdr] EnableProcessTelemetryLogging: ObOpenObjectByPointer failed: 0x%08X\n", status);
        return FALSE;
    }

    PROCESS_LOGGING_INFORMATION loggingInfo = { 0 };
    loggingInfo.Flags = 0x7F; // All 7 logging bits

    if (g_ZwSetInformationProcess == NULL) {
        ZwClose(hProcess);
        return FALSE;
    }
    status = g_ZwSetInformationProcess(
        hProcess,
        ProcessLoggingInformation,
        &loggingInfo,
        sizeof(loggingInfo)
    );
    if (!NT_SUCCESS(status)) {
        LOG_A(LOG_WARNING, "[RedEdr] EnableProcessTelemetryLogging: ZwSetInformationProcess failed: 0x%08X\n", status);
        success = FALSE;
    } else {
        success = TRUE;
    }

    ZwClose(hProcess);
    return success;
}



int InitCallbacks() {
    UNICODE_STRING funcName;
    RtlInitUnicodeString(&funcName, L"ZwSetInformationProcess");
    g_ZwSetInformationProcess = (PFN_ZwSetInformationProcess)MmGetSystemRoutineAddress(&funcName);
    if (g_ZwSetInformationProcess == NULL) {
        LOG_A(LOG_WARNING, "[RedEdr] InitCallbacks: failed to resolve ZwSetInformationProcess\n");
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

        //LOG_A(LOG_INFO, "[RedEdr] Process %wZ created\n", processName);
        //LOG_A(LOG_INFO, "            PID: %d\n", pid);
        //LOG_A(LOG_INFO, "            Created by: %wZ\n", parent_processName);
        //LOG_A(LOG_INFO, "            ImageBase: %ws\n", createInfo->ImageFileName->Buffer);

        POBJECT_NAME_INFORMATION objFileDosDeviceName;
        IoQueryFileDosDeviceName(createInfo->FileObject, &objFileDosDeviceName);
        //LOG_A(LOG_INFO, "            DOS path: %ws\n", objFileDosDeviceName->Name.Buffer);
        //LOG_A(LOG_INFO, "            CommandLine: %ws\n", createInfo->CommandLine->Buffer);

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
        //LOG_A(LOG_INFO, "CreateProcessNotify: Process %d created, observe: %i\n", 
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

        // Enable all ETW-TI logging flags so Microsoft-Windows-Threat-Intelligence
        // emits the full range of events (ReadVM, WriteVM, SetContextThread, etc.)
        // for this process. Applied to all new processes; RedEdrPplService filters
        // by observe flag. Must run at PASSIVE_LEVEL - process callbacks qualify.
        BOOLEAN etwtiEnabledSuccess = EnableProcessTelemetryLogging(process);
        LOG_A(LOG_INFO, "Enabled ETW-TI logging for pid %d: %d\n", pid, etwtiEnabledSuccess);
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
                    LOG_A(LOG_INFO, "Injected DLL into pid: %d\n", ProcessId);
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
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "ObCallbackTest: CBTdPreOperationCallback: ignore process open/duplicate from the protected process itself\n");
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
            DbgPrintEx(
                DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL,
                "ObCallbackTest: CBTdPreOperationCallback: ignore thread open/duplicate from the protected process itself\n");
            goto Exit;
        }

        ObjectTypeName = L"PsThreadType";
        AccessBitsToClear = CB_THREAD_TERMINATE;
        AccessBitsToSet = 0;
    }
    else {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "ObCallbackTest: CBTdPreOperationCallback: unexpected object type\n");
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
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: CBTdPreOperationCallback: PROTECTED process %p (ID 0x%p)\n",
        TdProtectedTargetProcess,
        (PVOID)TdProtectedTargetProcessId
    );*/

    if (1) {
        char line[DATA_BUFFER_SIZE] = { 0 };
        RtlStringCbPrintfA(line, DATA_BUFFER_SIZE, "%p:%p;%p;%ls;%ls;%d,0x%x,0x%x,0x%x",
            /*"ObCallbackTest: CBTdPreOperationCallback\n"
            "    Client Id:    %p:%p\n"
            "    Object:       %p\n"
            "    Type:         %ls\n"
            "    Operation:    %ls (KernelHandle=%d)\n"
            "    OriginalDesiredAccess: 0x%x\n"
            "    DesiredAccess (in):    0x%x\n"
            "    DesiredAccess (out):   0x%x\n",*/
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
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "ObCallbackTest: CBTdPreOperationCallback\n"
            "    Client Id:    %p:%p\n"
            "    Object:       %p\n"
            "    Type:         %ls\n"
            "    Operation:    %ls (KernelHandle=%d)\n"
            "    OriginalDesiredAccess: 0x%x\n"
            "    DesiredAccess (in):    0x%x\n"
            "    DesiredAccess (out):   0x%x\n",
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

