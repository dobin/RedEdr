#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>

#include "common.h"


int inject_dll(int pid) {
    UNICODE_STRING pipeName; // String containing the name of the named
    // Initialize a UNICODE_STRING structure containing the name of the named pipe
    RtlInitUnicodeString(
        &pipeName,                      // Variable in which we will store the UNICODE_STRING structure
        L"\\??\\pipe\\dumbedr-injector" // Wide string containing the name of the named pipe
    );

    HANDLE hPipe2;                     // Handle that we will use to communicate with the named pipe
    OBJECT_ATTRIBUTES fattrs = { 0 }; // Objects Attributes used to store information when calling ZwCreateFile
    IO_STATUS_BLOCK io_stat_block;    // IO status block used to specify the state of a I/O request

    // Initialize an OBJECT_ATTRIBUTE structure pointing to our named pipe
    InitializeObjectAttributes(&fattrs, &pipeName, OBJ_CASE_INSENSITIVE | 0x0200, 0, NULL);

    NTSTATUS status = ZwCreateFile(
        &hPipe2,                                         // Handle to the named pipe
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

        wchar_t pid_to_inject[MESSAGE_SIZE] = { 0 };
        swprintf_s(pid_to_inject, MESSAGE_SIZE, L"%d\0", pid);
        // Now we'll send the binary path to the userland agent
        status = ZwWriteFile(
            hPipe2,          // Handle to the named pipe
            NULL,           // Optionally a handle on an even object
            NULL,           // Always NULL
            NULL,           // Always NULL
            &io_stat_block, // Structure containing the I/O queue
            pid_to_inject,  // Buffer in which is stored the binary path
            MESSAGE_SIZE,   // Maximum size of the buffer
            NULL,           // Bytes offset (optional)
            NULL            // Always NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWriteFile: 0x%0.8x\n", status);

        /*
        This function is needed when you are running read/write files operation so that the kernel driver
        makes sure that the reading/writing phase is done and you can keep running the code
        */

        status = ZwWaitForSingleObject(
            hPipe2, // Handle the named pipe
            FALSE, // Whether or not we want the wait to be alertable
            NULL   // An optional timeout
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWaitForSingleObject: 0x%0.8x\n", status);

        wchar_t response[MESSAGE_SIZE] = { 0 };
        // Reading the response from the named pipe (ie: if the binary is malicious or not based on static analysis)
        status = ZwReadFile(
            hPipe2,          // Handle to the named pipe
            NULL,           // Optionally a handle on an even object
            NULL,           // Always NULL
            NULL,           // Always NULL
            &io_stat_block, // Structure containing the I/O queue
            &response,      // Buffer in which to store the answer
            MESSAGE_SIZE,   // Maximum size of the buffer
            NULL,           // Bytes offset (optional)
            NULL            // Always NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwReadFile: 0x%0.8x\n", status);

        // Waiting again for the operation to be completed
        status = ZwWaitForSingleObject(
            hPipe2,
            FALSE,
            NULL
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            ZwWaitForSingleObject: 0x%0.8x\n", status);

        // Used to close a connection to the named pipe
        ZwClose(
            hPipe2 // Handle to the named pipe
        );

        if (wcscmp(response, L"OK\0") == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector: OK\n", response);
            return 0;
        }
        else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector: KO\n", response);
            return 1;
        }
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "            RemoteInjector unreachable. Allowing.\n");
        return 0;
    }
}
