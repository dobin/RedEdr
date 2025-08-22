#include <Ntifs.h>
#include <ntddk.h>
#include <stdio.h>

#include "upipe.h"
#include "kapcinjector.h"
#include "kcallbacks.h"
#include "hashcache.h"
#include "settings.h"
#include "utils.h"
#include "../Shared/common.h"


char* ProcessLine;
char* ImageLine;
char* ThreadLine;


int InitCallbacks() {
    ProcessLine = ExAllocatePool2(POOL_FLAG_NON_PAGED, DATA_BUFFER_SIZE, 'log');
    if (ProcessLine == NULL) {
        return FALSE;
    }
    ImageLine = ExAllocatePool2(POOL_FLAG_NON_PAGED, DATA_BUFFER_SIZE, 'log');
    if (ImageLine == NULL) {
        return FALSE;
    }
    ThreadLine = ExAllocatePool2(POOL_FLAG_NON_PAGED, DATA_BUFFER_SIZE, 'log');
    if (ThreadLine == NULL) {
        return FALSE;
    }
    return TRUE;
}

void UninitCallbacks() {
    ExFreePool(ProcessLine);
    ExFreePool(ImageLine);
    ExFreePool(ThreadLine);
}


// For: PsSetCreateProcessNotifyRoutineEx()
void CreateProcessNotifyRoutine(PEPROCESS parent_process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo) {
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
        PEPROCESS process = NULL;
        PUNICODE_STRING processName = NULL;

        PsLookupProcessByProcessId(pid, &process);
        SeLocateProcessImageName(process, &processName);


        PsLookupProcessByProcessId(createInfo->ParentProcessId, &parent_process);
        PUNICODE_STRING parent_processName = NULL;
        SeLocateProcessImageName(parent_process, &parent_processName);

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
    }

    if (g_Settings.enable_logging && processInfo->observe) {
        char processName[PROC_NAME_LEN];
        char parentName[PROC_NAME_LEN];

        NTSTATUS status;
        status = WcharToAscii(processInfo->name, wcslen(processInfo->name), processName, sizeof(processName));
        status = WcharToAscii(processInfo->parent_name, wcslen(processInfo->parent_name), parentName, sizeof(parentName));
        JsonEscape(processName, PROC_NAME_LEN);
        JsonEscape(parentName, PROC_NAME_LEN);

        sprintf(ProcessLine, "{\"type\":\"kernel\",\"time\":%llu,\"func\":\"process_create\",\"krn_pid\":%llu,\"pid\":%llu,\"name\":\"%s\",\"ppid\":%llu,\"parent_name\":\"%s\"}",
            systemTime,
            (unsigned __int64)PsGetCurrentProcessId(),
            (unsigned __int64)pid, 
            processName,
            (unsigned __int64)createInfo->ParentProcessId, 
            parentName);
        LogEvent(ProcessLine);
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

    sprintf(ThreadLine, "{\"type\":\"kernel\",\"time\":%llu,\"func\":\"thread_create\",\"krn_pid\":%llu,\"pid\":%llu,\"threadid\":%llu,\"create\":%d}",
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
            sprintf(ImageLine, "{\"type\":\"kernel\",\"time\":%llu,\"func\":\"image_load\",\"krn_pid\":%llu,\"pid\":%llu,\"image\":\"%s\"}",
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
        if (processInfo != NULL && processInfo->observe && !processInfo->injected) {
            processInfo->injected = KapcInjectDll(FullImageName, ProcessId, ImageInfo);
            // TODO lock this?
            if (processInfo->injected) {
                LOG_A(LOG_INFO, "Injected DLL into pid: %d\n", ProcessId);
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

    TdSetCallContext(PreInfo, CallbackRegistration);


    /*DbgPrintEx(
        DPFLTR_IHVDRIVER_ID, DPFLTR_TRACE_LEVEL, "ObCallbackTest: CBTdPreOperationCallback: PROTECTED process %p (ID 0x%p)\n",
        TdProtectedTargetProcess,
        (PVOID)TdProtectedTargetProcessId
    );*/

    if (1) {
        char line[DATA_BUFFER_SIZE] = { 0 };
        sprintf(line, "%p:%p;%p;%ls;%ls;%d,0x%x,0x%x,0x%x",
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

