#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

#include "common.h"
#include "pipe.h"
#include "kcallbacks.h"


// For: PsSetCreateProcessNotifyRoutineEx()
void CreateProcessNotifyRoutine(PEPROCESS parent_process, HANDLE pid, PPS_CREATE_NOTIFY_INFO createInfo) {
    UNREFERENCED_PARAMETER(parent_process);

    PEPROCESS process = NULL;
    PUNICODE_STRING processName = NULL;

    PsLookupProcessByProcessId(pid, &process);
    SeLocateProcessImageName(process, &processName);

    wchar_t line[MESSAGE_SIZE] = { 0 };

    // Never forget this if check because if you don't, you'll end up crashing your Windows system ;P
    if (createInfo != NULL) {
        createInfo->CreationStatus = STATUS_SUCCESS;

        // Retrieve parent process ID and process name
        PsLookupProcessByProcessId(createInfo->ParentProcessId, &parent_process);
        PUNICODE_STRING parent_processName = NULL;
        SeLocateProcessImageName(parent_process, &parent_processName);

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Process %wZ created\n", processName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PID: %d\n", pid);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            Created by: %wZ\n", parent_processName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ImageBase: %ws\n", createInfo->ImageFileName->Buffer);

        POBJECT_NAME_INFORMATION objFileDosDeviceName;
        IoQueryFileDosDeviceName(createInfo->FileObject, &objFileDosDeviceName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            DOS path: %ws\n", objFileDosDeviceName->Name.Buffer);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            CommandLine: %ws\n", createInfo->CommandLine->Buffer);

        swprintf(line, L"process:%llu;%wZ;%llu;%wZ",
            (unsigned __int64)pid, processName,
            (unsigned __int64)createInfo->ParentProcessId, parent_processName);
        log_event(line);
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Process %wZ killed\n", processName);
    }
}


// For: PsSetCreateThreadNotifyRoutine()
void CreateThreadNotifyRoutine(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create) {
    wchar_t line[MESSAGE_SIZE] = { 0 };
    swprintf(line, L"thread:%llu;%llu;%d",
        (unsigned __int64)ProcessId,
        (unsigned __int64)ThreadId,
        Create);
    log_event(line);

    if ((uintptr_t)ProcessId == 700) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Thread %d created\n", ThreadId);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PID: %d  %d\n", ProcessId, Create);
    }
}


// For: PsSetLoadImageNotifyRoutine
void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo) {
    wchar_t line[MESSAGE_SIZE] = { 0 };
    swprintf(line, L"image:%llu;%wZ",
        (unsigned __int64)ProcessId,
        FullImageName);
    log_event(line);

    if ((uintptr_t)ProcessId == 700) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Image %wZ created\n", FullImageName);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PID: %d\n", ProcessId);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            Image Info: %d\n", ImageInfo);
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
        wchar_t line[MESSAGE_SIZE] = { 0 };
        swprintf(line, L"%p:%p;%p;%ls;%ls;%d,0x%x,0x%x,0x%x",
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
        log_event(line);
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

