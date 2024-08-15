#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

#include "common.h"


// Handle that we will use to communicate with the named pipe to userspace
HANDLE hPipe = NULL;


// log the event message (write to pipe)
int log_event(wchar_t* message) {
    if (hPipe == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "LogEvent: cannot log as pipe is closed");
        return 1;
    }
    NTSTATUS status;
    IO_STATUS_BLOCK io_stat_block;
    ULONG len = (ULONG) wcslen(message) * 2;
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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "LogEvent: ZwWriteFile: Error ZwWriteFile: 0x%0.8x\n", status);
        hPipe = NULL;
        return 0;
    }
    return 1;
}


void close_pipe() {
    ZwClose(hPipe);
}


// Connect to the userspace daemon
int InitDllPipe() {
    UNICODE_STRING pipeName;
    RtlInitUnicodeString(&pipeName, L"\\??\\pipe\\RedEdrKrnCom");

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
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "InitDllPipe: OK.\n");
        return 1;
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, 
            "InitDllPipe: ERROR, Daemon not running?.\n");
        hPipe = NULL;
        return 0;
    }
}

