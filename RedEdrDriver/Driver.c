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
#include "kcallbacks.h"
#include "hashcache.h"
#include "../Shared/common.h"

// Internal driver device name, cannot be used userland
UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\RedEdr");

// Symlink used to reach the driver, can be used userland
UNICODE_STRING SYM_LINK = RTL_CONSTANT_STRING(L"\\??\\RedEdr");


// To remove ObRegisterCallback at the end
PVOID pCBRegistrationHandle = NULL;


NTSTATUS MyDriverDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG controlCode = stack->Parameters.DeviceIoControl.IoControlCode;

    UNREFERENCED_PARAMETER(DeviceObject);

    switch (controlCode) {
    case IOCTL_MY_IOCTL_CODE: {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RedEdr] Handling IOCTL\n");

        // read IOCTL
        PMY_DRIVER_DATA data = (PMY_DRIVER_DATA)Irp->AssociatedIrp.SystemBuffer;
        size_t inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;

        if (inputBufferLength != sizeof(MY_DRIVER_DATA)) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Size error: %i %i\n", 
                inputBufferLength, sizeof(data));
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Received from user-space: %i: %i %s\n", inputBufferLength, data->flag, data->filename);
        char* answer;
        if (data->flag) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Enable\n");
            g_config.enable_kapc_injection = 1;
            g_config.enable_logging = 1;
            wcscpy_s(g_config.target, sizeof(g_config.target), data->filename);

            int ret = InitPipeToUserspace();
            if (ret) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  OK: %d bytes\n", ret);
                answer = "OK";
            }
            else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  FAIL Not Enabled: %d\n", ret);
                answer = "FAIL";
            }
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  Disable\n");
            g_config.enable_kapc_injection = 0;
            g_config.enable_logging = 0;
            wcscpy_s(g_config.target, sizeof(g_config.target), data->filename); // should be zero
            close_pipe();
            answer = "OK";
        }

        // Answer IOCTL
        size_t messageLen = strlen(answer) + 1;
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, answer, messageLen);
        Irp->IoStatus.Information = (ULONG) messageLen;
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}


void LoadKernelCallbacks() {
    NTSTATUS ret;

    // Process
    if (g_config.init_processnotify) {
        ret = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);
        if (ret == STATUS_SUCCESS) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[OK] CreateProcessNotifyRoutine launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ERROR] CreateProcessNotifyRoutine Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ERROR] CreateProcessNotifyRoutine Access denied\n");
        }
    }
    
    // Thread
    if (g_config.init_threadnotify) {
        ret = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
        if (ret == STATUS_SUCCESS) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[OK] CreateThreadNotifyRoutine launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ERROR] CreateThreadNotifyRoutine Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ERROR] CreateThreadNotifyRoutine Access denied\n");
        }
    }

    // Image
    if (g_config.init_imagenotify) {
        ret = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
        if (ret == STATUS_SUCCESS) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[OK] LoadImageNotifyRoutine launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ERROR] LoadImageNotifyRoutine Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ERROR] LoadImageNotifyRoutine Access denied\n");
        }
    }

    // Open
    if (g_config.init_obnotify) {
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
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[OK] ObRegister launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ERROR] ObRegister Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ERROR] ObRegister Access denied\n");
        }
    }
}


void RedEdrUnload(_In_ PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Unloading routine called\n");

    close_pipe();

    // Unset the callback
    PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
    PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
    PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    if (pCBRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(pCBRegistrationHandle);
    }

    // Remove all data
    FreeHashTable();

    // Delete the driver device 
    IoDeleteDevice(DriverObject->DeviceObject);
    // Delete the symbolic link
    IoDeleteSymbolicLink(&SYM_LINK);
}


NTSTATUS MyDriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}


NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath); // Prevent compiler error such as unreferenced parameter (error 4)
    NTSTATUS status;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RedEdr] 0.2 Initializing the EDR's driver\n");
    InitializeHashTable();

    // Setting the unload routine to execute
    DriverObject->DriverUnload = RedEdrUnload;

    // IOCTL
    DriverObject->MajorFunction[IRP_MJ_CREATE] = MyDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = MyDriverCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = MyDriverDeviceControl;

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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RedEdr] Device creation failed\n");
        return status;
    }

    // Creating the symlink that we will use to contact our driver
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[RedEdr] Symlink creation failed\n");
        IoDeleteDevice(DeviceObject);
        return status;
    }

    init_config();
    LoadKernelCallbacks(); // always load the callbacks, based on config
    if (g_config.enable_logging) { // only connect when we enable this (deamon may not be ready on load)
        InitPipeToUserspace();
    }

    return STATUS_SUCCESS;
}

