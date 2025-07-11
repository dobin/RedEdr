#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <fltkernel.h>

#include "../Shared/common.h"
#include "utils.h"
#include "upipe.h"


// Handle that we will use to communicate with the named pipe to userspace
HANDLE hPipe = NULL;

// Spinlock to protect pipe handle access
KSPIN_LOCK pipeLock;
KIRQL oldIrql;


// Initialize the pipe subsystem
void InitializePipe() {
    KeInitializeSpinLock(&pipeLock);
    hPipe = NULL;
}

// Cleanup the pipe subsystem
void CleanupPipe() {
    DisconnectUserspacePipe();
}


int IsUserspacePipeConnected() {
    BOOLEAN connected;
    KeAcquireSpinLock(&pipeLock, &oldIrql);
    connected = (hPipe != NULL);
    KeReleaseSpinLock(&pipeLock, oldIrql);
    return connected;
}


// log the event message (write to pipe)
int LogEvent(char* message) {
    if (message == NULL) {
        LOG_A(LOG_INFO, "uPipe: message parameter is NULL");
        return 0;
    }

    HANDLE currentPipe;
    KeAcquireSpinLock(&pipeLock, &oldIrql);
    currentPipe = hPipe;
    KeReleaseSpinLock(&pipeLock, oldIrql);

    if (currentPipe == NULL) {
        LOG_A(LOG_INFO, "uPipe: cannot log as pipe is closed");
        return 0;
    }

    NTSTATUS status;
    IO_STATUS_BLOCK io_stat_block;
    ULONG len = (ULONG) strlen(message);
    
    // Validate message length
    if (len == 0 || len > PIPE_BUFFER_SIZE - 1) {
        LOG_A(LOG_INFO, "uPipe: invalid message length: %lu", len);
        return 0;
    }
    
    len += 1; // include end \x00
    
    status = ZwWriteFile(
        currentPipe,
        NULL,
        NULL,
        NULL,
        &io_stat_block,
        message,
        len,
        NULL,
        NULL
    );
    if (!NT_SUCCESS(status)) {
        LOG_A(LOG_INFO, 
            "uPipe: ZwWriteFile: Error ZwWriteFile: 0x%0.8x", status);
        
        // Mark pipe as disconnected on error
        KeAcquireSpinLock(&pipeLock, &oldIrql);
        hPipe = NULL;
        KeReleaseSpinLock(&pipeLock, oldIrql);
        return 0;
    }
    return 1;
}


void DisconnectUserspacePipe() {
    HANDLE pipeToClose = NULL;
    
    KeAcquireSpinLock(&pipeLock, &oldIrql);
    pipeToClose = hPipe;
    hPipe = NULL;
    KeReleaseSpinLock(&pipeLock, oldIrql);
    
    if (pipeToClose != NULL) {
        ZwClose(pipeToClose);
        LOG_A(LOG_INFO, "uPipe: Disconnected from userspace server");
    }
}


// Connect to the userspace daemon
int ConnectUserspacePipe() {
    UNICODE_STRING pipeName;
    RtlInitUnicodeString(&pipeName, DRIVER_KERNEL_PIPE_NAME);

    OBJECT_ATTRIBUTES fattrs = { 0 };
    IO_STATUS_BLOCK io_stat_block;
    HANDLE newPipe = NULL;

    InitializeObjectAttributes(&fattrs, &pipeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, NULL);

    NTSTATUS status = ZwCreateFile(
        &newPipe,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &fattrs,
        &io_stat_block,
        NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );
    if (NT_SUCCESS(status)) {
        KeAcquireSpinLock(&pipeLock, &oldIrql);
        hPipe = newPipe;
        KeReleaseSpinLock(&pipeLock, oldIrql);
        
        LOG_A(LOG_INFO, "uPipe: Connected to userspace server successfully");
        return 1;
    }
    else {
        LOG_A(LOG_INFO, "uPipe: Could not connect to userspace server (status: 0x%0.8x), RedEdr.exe --kernel running?", status);
        return 0;
    }
}

