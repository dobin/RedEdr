#pragma once

#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>


#define TD_CALLBACK_REGISTRATION_TAG  '0bCO' // TD_CALLBACK_REGISTRATION structure.
#define TD_CALL_CONTEXT_TAG           '1bCO' // TD_CALL_CONTEXT structure.


/** For ObRegisterCallbacks **/
typedef struct _TD_CALLBACK_PARAMETERS {
    ACCESS_MASK AccessBitsToClear;
    ACCESS_MASK AccessBitsToSet;
}
TD_CALLBACK_PARAMETERS, * PTD_CALLBACK_PARAMETERS;
typedef struct _TD_CALLBACK_REGISTRATION {
    // Handle returned by ObRegisterCallbacks.
    PVOID RegistrationHandle;

    // If not NULL, filter only requests to open/duplicate handles to this
    // process (or one of its threads).
    PVOID TargetProcess;
    HANDLE TargetProcessId;

    // Currently each TD_CALLBACK_REGISTRATION has at most one process and one
    // thread callback. That is, we can't register more than one callback for
    // the same object type with a single ObRegisterCallbacks call.
    TD_CALLBACK_PARAMETERS ProcessParams;
    TD_CALLBACK_PARAMETERS ThreadParams;

    // Index in the global TdCallbacks array.
    ULONG RegistrationId;
}
TD_CALLBACK_REGISTRATION, * PTD_CALLBACK_REGISTRATION;


void CreateProcessNotifyRoutine(PEPROCESS, HANDLE, PPS_CREATE_NOTIFY_INFO);
void CreateThreadNotifyRoutine(HANDLE, HANDLE, BOOLEAN);
void LoadImageNotifyRoutine(PUNICODE_STRING, HANDLE, PIMAGE_INFO);
OB_PREOP_CALLBACK_STATUS CBTdPreOperationCallback(PVOID, POB_PRE_OPERATION_INFORMATION);
