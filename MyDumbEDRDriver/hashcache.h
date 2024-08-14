#pragma once

#include <ntddk.h>
#include <string.h>
#include <stdio.h>

typedef struct _PROCESS_INFO {
    HANDLE ProcessId;
    wchar_t name[128];

    HANDLE ppid;
    wchar_t parent_name[128];

    int observe;
    int injected;
} PROCESS_INFO, * PPROCESS_INFO;

NTSTATUS InitializeHashTable();
NTSTATUS AddProcessInfo(HANDLE ProcessId, PPROCESS_INFO ProcessInfo);
PPROCESS_INFO LookupProcessInfo(HANDLE ProcessId);
NTSTATUS RemoveProcessInfo(HANDLE ProcessId);
VOID FreeHashTable();
