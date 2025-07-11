#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <fltkernel.h>

// Needs to be set on the project properties as well
#pragma comment(lib, "FltMgr.lib")

#include "settings.h"
#include "utils.h"
#include "upipe.h"
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

    // Ensure we're at correct IRQL level for operations
    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        LOG_A(LOG_INFO, "[IOCTL] Invalid IRQL level for operation\n");
        status = STATUS_INVALID_DEVICE_STATE;
        Irp->IoStatus.Status = status;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    switch (controlCode) {
    case IOCTL_MY_IOCTL_CODE: {
        LOG_A(LOG_INFO, "[IOCTL] Handling IOCTL\n");

        // Validate input buffer
        size_t inputBufferLength = stack->Parameters.DeviceIoControl.InputBufferLength;
        
        if (inputBufferLength < sizeof(MY_DRIVER_DATA) || 
            Irp->AssociatedIrp.SystemBuffer == NULL) {
            LOG_A(LOG_INFO, "[IOCTL] Invalid input buffer: size=%zu, expected=%zu\n", 
                inputBufferLength, sizeof(MY_DRIVER_DATA));
            status = STATUS_INVALID_PARAMETER;
            Irp->IoStatus.Information = 0;
            break;
        }

        // read IOCTL
        PMY_DRIVER_DATA data = (PMY_DRIVER_DATA)Irp->AssociatedIrp.SystemBuffer;
        
        // Ensure filename is null-terminated
        data->filename[TARGET_WSTR_LEN - 1] = L'\0';

        LOG_A(LOG_INFO, "[IOCTL] Received from user-space: enabled: %i/%i  filename: %ls\n", 
            data->enable, data->dll_inject, data->filename);
        char* answer;
        if (data->enable) {
            if (data->dll_inject) {
                g_Settings.enable_kapc_injection = 1;
            }
            g_Settings.enable_logging = 1;
            wcscpy_s(g_Settings.target, TARGET_WSTR_LEN, data->filename);

            if (!IsUserspacePipeConnected()) {
                int ret = ConnectUserspacePipe();
                if (ret) {
                    LOG_A(LOG_INFO, "[IOCTL] Start OK\n");
                    answer = "OK";
                }
                else {
                    LOG_A(LOG_INFO, "[IOCTL] Start ERROR\n");
                    answer = "FAIL";
                }
            }
            else {
                answer = "OK";
            }
        }
        else {
            LOG_A(LOG_INFO, "[IOCTL] Stop\n");
            g_Settings.enable_kapc_injection = 0;
            g_Settings.enable_logging = 0;
            wcscpy_s(g_Settings.target, TARGET_WSTR_LEN, data->filename); // should be zero
            DisconnectUserspacePipe();
            answer = "OK";
        }

        // Answer IOCTL - Validate output buffer size
        size_t messageLen = strlen(answer) + 1;
        size_t outputBufferLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
        
        if (outputBufferLength < messageLen) {
            LOG_A(LOG_INFO, "[IOCTL] Output buffer too small: %zu < %zu\n", 
                outputBufferLength, messageLen);
            status = STATUS_BUFFER_TOO_SMALL;
            Irp->IoStatus.Information = messageLen;
            break;
        }
        
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
    if (g_Settings.init_processnotify) {
        ret = PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);
        if (ret == STATUS_SUCCESS) {
            LOG_A(LOG_INFO, "CreateProcessNotifyRoutine launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            LOG_A(LOG_INFO, "ERROR: CreateProcessNotifyRoutine Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            LOG_A(LOG_INFO, "ERROR: CreateProcessNotifyRoutine Access denied\n");
        }
    }
    
    // Thread
    if (g_Settings.init_threadnotify) {
        ret = PsSetCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
        if (ret == STATUS_SUCCESS) {
            LOG_A(LOG_INFO, "CreateThreadNotifyRoutine launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            LOG_A(LOG_INFO, "ERROR: CreateThreadNotifyRoutine Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            LOG_A(LOG_INFO, "ERROR: CreateThreadNotifyRoutine Access denied\n");
        }
    }

    // Image
    if (g_Settings.init_imagenotify) {
        ret = PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
        if (ret == STATUS_SUCCESS) {
            LOG_A(LOG_INFO, "LoadImageNotifyRoutine launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            LOG_A(LOG_INFO, "ERROR: LoadImageNotifyRoutine Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            LOG_A(LOG_INFO, "ERROR: LoadImageNotifyRoutine Access denied\n");
        }
    }

    // Open
    if (g_Settings.init_obnotify) {
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
            LOG_A(LOG_INFO, "ObRegister launched successfully\n");
        }
        else if (ret == STATUS_INVALID_PARAMETER) {
            LOG_A(LOG_INFO, "ERROR: ObRegister Invalid parameter\n");
        }
        else if (ret == STATUS_ACCESS_DENIED) {
            LOG_A(LOG_INFO, "ERROR: ObRegister Access denied\n");
        }
    }
}


void RedEdrUnload(_In_ PDRIVER_OBJECT DriverObject) {
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "Unloading routine called\n");

    CleanupPipe();

    // Unset the callbacks only if they were set
    if (g_Settings.init_processnotify) {
        PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);
    }
    if (g_Settings.init_threadnotify) {
        PsRemoveCreateThreadNotifyRoutine(CreateThreadNotifyRoutine);
    }
    if (g_Settings.init_imagenotify) {
        PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
    }
    if (pCBRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(pCBRegistrationHandle);
        pCBRegistrationHandle = NULL;
    }

    // Remove all data
    FreeHashTable();
    UninitCallbacks();

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

    LOG_A(LOG_INFO, "RedEdr Kernel Driver %s\n", REDEDR_VERSION);
    InitializeHashTable();
    InitializePipe();

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
        FILE_DEVICE_SECURE_OPEN,   // characteristics flags - require admin access,
        FALSE,				   // not exclusive,
        &DeviceObject		   // the resulting pointer
    );
    if (!NT_SUCCESS(status)) {
        LOG_A(LOG_INFO, "Device creation failed\n");
        return status;
    }

    // Creating the symlink that we will use to contact our driver
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    if (!NT_SUCCESS(status)) {
        LOG_A(LOG_INFO, "Symlink creation failed\n");
        IoDeleteDevice(DeviceObject);
        return status;
    }

    InitCallbacks();
    init_settings();
    LoadKernelCallbacks(); // always load the callbacks, based on config
    if (g_Settings.enable_logging) { // only connect when we enable this (deamon may not be ready on load)
        if (!ConnectUserspacePipe()) {
            LOG_A(LOG_INFO, "Warning: Failed to connect userspace pipe during driver load\n");
        }
    }

    LOG_A(LOG_INFO, "RedEdr driver loaded successfully\n");
    return STATUS_SUCCESS;
}

