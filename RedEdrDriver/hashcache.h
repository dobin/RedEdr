#pragma once

#include <ntddk.h>
#include <string.h>
#include <stdio.h>


#define PROC_NAME_LEN 128

typedef struct _PROCESS_INFO {
    HANDLE ProcessId;
    wchar_t name[PROC_NAME_LEN];

    HANDLE ppid;
    wchar_t parent_name[PROC_NAME_LEN];

    int observe;
    int injected;
} PROCESS_INFO, * PPROCESS_INFO;


#define HASH_TABLE_SIZE 256

typedef struct _HASH_ENTRY {
    HANDLE ProcessId;
    PPROCESS_INFO ProcessInfo;
    struct _HASH_ENTRY* Next;
} HASH_ENTRY, * PHASH_ENTRY;


NTSTATUS InitializeHashTable();
NTSTATUS AddProcessInfo(HANDLE ProcessId, PPROCESS_INFO ProcessInfo);
PPROCESS_INFO LookupProcessInfo(HANDLE ProcessId);
NTSTATUS RemoveProcessInfo(HANDLE ProcessId);
VOID FreeHashTable();
ULONG HashFunction(HANDLE ProcessId);