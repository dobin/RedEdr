#pragma once

#ifndef COMMON_H
#define COMMON_H

#define PIPE_BUFFER_SIZE 8192 // thats the pipe buffer (default 4096)
#define DATA_BUFFER_SIZE 8192 // events, most important

#define IOCTL_MY_IOCTL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// PATH_LEN > TARGET_WSTR_LEN
#define TARGET_WSTR_LEN 128
#define PATH_LEN 1024

#define DLL_CONFIG_LEN 256 // for DLL pipe
#define PPL_CONFIG_LEN 256 // for PPL pipe

// Kernel
#define KRN_CONFIG_LEN 128 // for Kernel pipe
typedef struct _MY_DRIVER_DATA {
    wchar_t filename[TARGET_WSTR_LEN];
    int enable;
    int dll_inject;
} MY_DRIVER_DATA, * PMY_DRIVER_DATA;

#define REDEDR_VERSION "0.4"

#define DRIVER_KERNEL_PIPE_NAME L"\\??\\pipe\\RedEdrKrnCom"
#define KERNEL_PIPE_NAME L"\\\\.\\pipe\\RedEdrKrnCom"
#define DLL_PIPE_NAME L"\\\\.\\pipe\\RedEdrDllCom"

#define PPL_SERVICE_PIPE_NAME L"\\\\.\\pipe\\RedEdrPplService"
#define PPL_DATA_PIPE_NAME L"\\\\.\\pipe\\RedEdrPplData"
#define SERVICE_NAME  L"RedEdrPplService"

#define DRIVER_NAME L"c:\\RedEdr\\elam_driver.sys"

#define MAX_CALLSTACK_ENTRIES 8

#endif