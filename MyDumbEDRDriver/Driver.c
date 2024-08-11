#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

// Needs to be set on the project properties as well
#pragma comment(lib, "FltMgr.lib")

#include "config.h"
#include "pipe.h"
#include "common.h"
#include "kcallbacks.h"


// Internal driver device name, cannot be used userland
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\MyDumbEDR");

// Symlink used to reach the driver, can be used userland
UNICODE_STRING SYM_LINK = RTL_CONSTANT_STRING(L"\\??\\MyDumbEDR");


// To remove ObRegisterCallback at the end
PVOID pCBRegistrationHandle = NULL;


void LoadKernelCallbacks() {
    NTSTATUS ret;

    // Process
    if (g_config.enable_processnotify) {
        ret = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);
        if (ret == STATUS_SUCCESS) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateProcessNotifyRoutine launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateProcessNotifyRoutine Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateProcessNotifyRoutine Access denied\n");
        }
    }
    
    // Thread
    if (g_config.enable_threadnotify) {
        ret = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
        if (ret == STATUS_SUCCESS) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateThreadNotifyRoutine launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateThreadNotifyRoutine Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] CreateThreadNotifyRoutine Access denied\n");
        }
    }

    // Image
    if (g_config.enable_imagenotify) {
        ret = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
        if (ret == STATUS_SUCCESS) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] LoadImageNotifyRoutine launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] LoadImageNotifyRoutine Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] LoadImageNotifyRoutine Access denied\n");
        }
    }

    // Open
    if (g_config.enable_obnotify) {
        // https://github.com/microsoft/Windows-driver-samples/blob/main/general/obcallback/driver/callback.c
        OB_CALLBACK_REGISTRATION  CBObRegistration = { 0 };
        UNICODE_STRING CBAltitude = { 0 };
        RtlInitUnicodeString(&CBAltitude, L"1000");
        TD_CALLBACK_REGISTRATION CBCallbackRegistration = { 0 };

        OB_OPERATION_REGISTRATION CBOperationRegistrations[2] = { { 0 }, { 0 } };
        CBOperationRegistrations[0].ObjectType = PsProcessType;
        CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_CREATE;
        CBOperationRegistrations[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
        CBOperationRegistrations[0].PreOperation = CBTdPreOperationCallback;
        //CBOperationRegistrations[0].PostOperation = CBTdPostOperationCallback;

        CBOperationRegistrations[1].ObjectType = PsThreadType;
        CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_CREATE;
        CBOperationRegistrations[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
        CBOperationRegistrations[1].PreOperation = CBTdPreOperationCallback;
        //CBOperationRegistrations[1].PostOperation = CBTdPostOperationCallback;

        CBObRegistration.Version = OB_FLT_REGISTRATION_VERSION;
        CBObRegistration.OperationRegistrationCount = 2;
        CBObRegistration.Altitude = CBAltitude;
        CBObRegistration.RegistrationContext = &CBCallbackRegistration;
        CBObRegistration.OperationRegistration = CBOperationRegistrations;
        ret = ObRegisterCallbacks(&CBObRegistration, &pCBRegistrationHandle);
        if (ret == STATUS_SUCCESS) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] ObRegister launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] ObRegister Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] ObRegister Access denied\n");
        }
    }
}


void UnloadMyDumbEDR(_In_ PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[MyDumbEDR] Unloading routine called\n");

    close_pipe();

    // Unset the callback
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
    PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (pCBRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(pCBRegistrationHandle);
    }

    // Delete the driver device 
    IoDeleteDevice(DriverObject->DeviceObject);
    // Delete the symbolic link
    IoDeleteSymbolicLink(&SYM_LINK);
}


NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath); // Prevent compiler error such as unreferenced parameter (error 4)
    NTSTATUS status;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Initializing the EDR's driver\n");

    // Setting the unload routine to execute
    DriverObject->DriverUnload = UnloadMyDumbEDR;

    // Initializing a device object and creating it
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING deviceName = DEVICE_NAME;
    UNICODE_STRING symlinkName = SYM_LINK;
    status = IoCreateDevice(
        DriverObject,		   // our driver object,
        0,					   // no need for extra bytes,
        &deviceName,           // the device name,
        FILE_DEVICE_UNKNOWN,   // device type,
        0,					   // characteristics flags,
        FALSE,				   // not exclusive,
        &DeviceObject		   // the resulting pointer
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Device creation failed\n");
        return status;
    }

    // Creating the symlink that we will use to contact our driver
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[MyDumbEDR] Symlink creation failed\n");
        IoDeleteDevice(DeviceObject);
        return status;
    }

    init_config();
    open_pipe();
    LoadKernelCallbacks();

    return 0;
}

