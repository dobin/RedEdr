#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

#include "common.h"


// Handle that we will use to communicate with the named pipe
// To Userspace
HANDLE hPipe = NULL;


// log the event message
int log_event(wchar_t* message) {
    if (hPipe == NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            cannot log as pipe is closed");
        return 1;
    }
    NTSTATUS status;
    IO_STATUS_BLOCK io_stat_block;    // IO status block used to specify the state of a I/O request

    // Now we'll send the data path the userland agent
    status = ZwWriteFile(
        hPipe,            // Handle to the named pipe
        NULL,             // Optionally a handle on an even object
        NULL,             // Always NULL
        NULL,             // Always NULL
        &io_stat_block,   // Structure containing the I/O queue
        message, // Buffer in which is stored the binary path
        MESSAGE_SIZE,     // Maximum size of the buffer
        NULL,             // Bytes offset (optional)
        NULL              // Always NULL
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWriteFile: Error ZwWriteFile: 0x%0.8x\n", status);
        hPipe = NULL;
        return 0;
    }

    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            log_event(): %zW", message);
    /*status = ZwWaitForSingleObject(
        hPipe, // Handle the named pipe
        FALSE, // Whether or not we want the wait to be alertable
        NULL   // An optional timeout
    );
    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWriteFile: Error ZwWaitForSingleObject: 0x%0.8x\n", status);
        hPipe = NULL;
        return 0;
    }*/

    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWaitForSingleObject: 0x%0.8x\n", status);

    return 1;
}


// Close pipe
void close_pipe() {
    ZwClose(hPipe);
}


// Connect to the userspace daemon
int open_pipe() {
    UNICODE_STRING pipeName; // String containing the name of the named
    // Initialize a UNICODE_STRING structure containing the name of the named pipe
    RtlInitUnicodeString(
        &pipeName,                      // Variable in which we will store the UNICODE_STRING structure
        L"\\??\\pipe\\dumbedr-analyzer" // Wide string containing the name of the named pipe
    );

    OBJECT_ATTRIBUTES fattrs = { 0 }; // Objects Attributes used to store information when calling ZwCreateFile
    IO_STATUS_BLOCK io_stat_block;    // IO status block used to specify the state of a I/O request

    // Initialize an OBJECT_ATTRIBUTE structure pointing to our named pipe
    InitializeObjectAttributes(&fattrs, &pipeName, OBJ_CASE_INSENSITIVE | 0x0200, 0, NULL);

    // Reads from the named pipe
    NTSTATUS status = ZwCreateFile(
        &hPipe,                                         // Handle to the named pipe
        FILE_WRITE_DATA | FILE_READ_DATA | SYNCHRONIZE, // File attribute (we need both read and write)
        &fattrs,                                        // Structure containing the file attribute
        &io_stat_block,                                 // Structure containing the I/O queue
        NULL,                                           // Allocation size, not needed in that case
        0,                                              // Specific files attributes (not needed as well
        FILE_SHARE_READ | FILE_SHARE_WRITE,             // File sharing access
        FILE_OPEN,                                      // Specify the action we want to do on the file 
        FILE_NON_DIRECTORY_FILE,                        // Specifying that the file is not a directory
        NULL,                                           // Always NULL
        0                                               // Always zero
    );

    // If we can obtain a handle on the named pipe then 
    if (NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PIPE: OK.\n");
        return 1;
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            PIPE: ERROR, Daemon not running?.\n");
        hPipe = NULL;
        return 0;
    }
}

