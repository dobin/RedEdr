#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

#include "../Shared/common.h"
#include "utils.h"


// Handle that we will use to communicate with the named pipe to userspace
HANDLE hPipe = NULL;


// log the event message (write to pipe)
int LogEvent(wchar_t* message) {
    if (hPipe == NULL) {
        LOG_A(LOG_INFO, "uPipe: cannot log as pipe is closed");
        return 1;
    }
    NTSTATUS status;
    IO_STATUS_BLOCK io_stat_block;
    ULONG len = (ULONG) (wcslen(message)+1) * 2; // include end \x00\x00
    status = ZwWriteFile(
        hPipe,
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
        hPipe = NULL;
        return 0;
    }
    return 1;
}


void DisconnectUserspacePipe() {
    ZwClose(hPipe);
    hPipe = NULL;
}


// Connect to the userspace daemon
int ConnectUserspacePipe() {
    UNICODE_STRING pipeName;
    RtlInitUnicodeString(&pipeName, DRIVER_KERNEL_PIPE_NAME);

    OBJECT_ATTRIBUTES fattrs = { 0 };
    IO_STATUS_BLOCK io_stat_block;

    InitializeObjectAttributes(&fattrs, &pipeName, OBJ_CASE_INSENSITIVE | 0x0200, 0, NULL);

    NTSTATUS status = ZwCreateFile(
        &hPipe,
        FILE_WRITE_DATA | SYNCHRONIZE,
        &fattrs,
        &io_stat_block,
        NULL,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        NULL,
        0
    );
    if (NT_SUCCESS(status)) {
        LOG_A(LOG_INFO, "uPipe: Connecting to userspace server OK");
        return 1;
    }
    else {
        LOG_A(LOG_INFO, "uPipe: Could not connect to userspace server, RedEdr.exe --kernel running?\n");
        hPipe = NULL;
        return 0;
    }
}

