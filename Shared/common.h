#pragma once

#ifndef COMMON_H
#define COMMON_H

// Handle differences between kernel-mode and user-mode compilation
// Kernel mode is detected by _KERNEL_MODE (WDK) or NTDDK (ntddk.h included)
#if defined(_KERNEL_MODE) || defined(NTDDK) || defined(_NTDDK_)
// Kernel mode: ntddk.h or ntifs.h should already be included before this header
// They define ULONG, UCHAR, etc.
#else
// User mode: need Windows.h for types
#ifndef _WINDOWS_
#include <windows.h>
#endif
#endif

#define PIPE_BUFFER_SIZE 8192 // thats the pipe buffer (default 4096)
#define DATA_BUFFER_SIZE 8192 // events, most important

#define IOCTL_MY_IOCTL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_PROCESS_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

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
    int enable_dll_injection;
    int enable_etwti_events;
    int enable_etwti_events_defender;
} MY_DRIVER_DATA, * PMY_DRIVER_DATA;

// PS_PROTECTION manipulation via kernel driver DKOM
// Protection types (from ntddk.h / Windows internals)
#define PS_PROTECTED_TYPE_NONE           0
#define PS_PROTECTED_TYPE_PROTECTED_LIGHT 1
#define PS_PROTECTED_TYPE_PROTECTED       2

// Protection signers (from ntddk.h / Windows internals)
#define PS_PROTECTED_SIGNER_NONE          0
#define PS_PROTECTED_SIGNER_AUTHENTICODE  1
#define PS_PROTECTED_SIGNER_CODEGEN       2
#define PS_PROTECTED_SIGNER_ANTIMALWARE   3
#define PS_PROTECTED_SIGNER_LSA           4
#define PS_PROTECTED_SIGNER_WINDOWS       5
#define PS_PROTECTED_SIGNER_WINTCB        6
#define PS_PROTECTED_SIGNER_WINSYSTEM     7

typedef struct _SET_PROCESS_PROTECTION_DATA {
    ULONG ProcessId;            // PID of the process to modify
    UCHAR ProtectionSigner;     // PS_PROTECTED_SIGNER_* value
    UCHAR ProtectionType;       // PS_PROTECTED_TYPE_* value
    UCHAR ProtectionAudit;      // Audit flag (usually 0)
    UCHAR Reserved;
} SET_PROCESS_PROTECTION_DATA, * PSET_PROCESS_PROTECTION_DATA;

#define REDEDR_VERSION "1.0"

#define DRIVER_KERNEL_PIPE_NAME L"\\??\\pipe\\RedEdrKrnCom"
#define KERNEL_PIPE_NAME L"\\\\.\\pipe\\RedEdrKrnCom"
#define DLL_PIPE_NAME L"\\\\.\\pipe\\RedEdrDllCom"

#define PPL_SERVICE_PIPE_NAME L"\\\\.\\pipe\\RedEdrPplService"
#define PPL_DATA_PIPE_NAME L"\\\\.\\pipe\\RedEdrPplData"
#define SERVICE_NAME  L"RedEdrPplService"

#define DRIVER_NAME L"c:\\RedEdr\\elam_driver.sys"

#define MAX_CALLSTACK_ENTRIES 8


#define LOG_ERROR 0
#define LOG_WARNING 1
#define LOG_INFO 2
#define LOG_DEBUG 3

#endif