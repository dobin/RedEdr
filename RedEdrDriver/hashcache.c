#include <Ntifs.h>
#include <ntddk.h>
#include <wdf.h>
#include <string.h>
#include <stdio.h>
#include <fltkernel.h>


#include "hashcache.h"

#define HASH_TABLE_SIZE 256


typedef struct _HASH_ENTRY {
    HANDLE ProcessId;
    PPROCESS_INFO ProcessInfo;
    struct _HASH_ENTRY* Next;
} HASH_ENTRY, * PHASH_ENTRY;


PHASH_ENTRY HashTable[HASH_TABLE_SIZE];
KSPIN_LOCK HashTableLock;

NTSTATUS InitializeHashTable()
{
    RtlZeroMemory(HashTable, sizeof(HashTable));
    KeInitializeSpinLock(&HashTableLock);
    return STATUS_SUCCESS;
}

ULONG HashFunction(HANDLE ProcessId)
{
    return ((ULONG_PTR)ProcessId) % HASH_TABLE_SIZE;
}

NTSTATUS AddProcessInfo(HANDLE ProcessId, PPROCESS_INFO ProcessInfo)
{
    ULONG index = HashFunction(ProcessId);
    PHASH_ENTRY entry;

    entry = (PHASH_ENTRY)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(HASH_ENTRY), 'Hash');
    if (!entry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    entry->ProcessId = ProcessId;
    entry->ProcessInfo = ProcessInfo;
    entry->Next = NULL;

    KIRQL oldIrql;
    KeAcquireSpinLock(&HashTableLock, &oldIrql);

    entry->Next = HashTable[index];
    HashTable[index] = entry;

    KeReleaseSpinLock(&HashTableLock, oldIrql);

    return STATUS_SUCCESS;
}

PPROCESS_INFO LookupProcessInfo(HANDLE ProcessId)
{
    ULONG index = HashFunction(ProcessId);
    PHASH_ENTRY entry;

    KIRQL oldIrql;
    KeAcquireSpinLock(&HashTableLock, &oldIrql);

    entry = HashTable[index];
    while (entry) {
        if (entry->ProcessId == ProcessId) {
            KeReleaseSpinLock(&HashTableLock, oldIrql);
            return entry->ProcessInfo;
        }
        entry = entry->Next;
    }

    KeReleaseSpinLock(&HashTableLock, oldIrql);
    return NULL;
}

NTSTATUS RemoveProcessInfo(HANDLE ProcessId)
{
    ULONG index = HashFunction(ProcessId);
    PHASH_ENTRY entry, prevEntry = NULL;

    KIRQL oldIrql;
    KeAcquireSpinLock(&HashTableLock, &oldIrql);

    entry = HashTable[index];
    while (entry) {
        if (entry->ProcessId == ProcessId) {
            if (prevEntry) {
                prevEntry->Next = entry->Next;
            }
            else {
                HashTable[index] = entry->Next;
            }
            ExFreePoolWithTag(entry, 'pInf');
            KeReleaseSpinLock(&HashTableLock, oldIrql);
            return STATUS_SUCCESS;
        }
        prevEntry = entry;
        entry = entry->Next;
    }

    KeReleaseSpinLock(&HashTableLock, oldIrql);
    return STATUS_NOT_FOUND;
}


VOID FreeHashTable()
{
    ULONG i;
    PHASH_ENTRY entry, tempEntry;

    KIRQL oldIrql;
    KeAcquireSpinLock(&HashTableLock, &oldIrql);

    // Iterate through each bucket in the hash table
    for (i = 0; i < HASH_TABLE_SIZE; i++) {
        entry = HashTable[i];

        // Traverse the linked list in this bucket
        while (entry) {
            tempEntry = entry->Next;

            // Free the associated PROCESS_INFO structure if allocated separately
            if (entry->ProcessInfo) {
                ExFreePool(entry->ProcessInfo);
            }

            // Free the hash table entry itself
            ExFreePool(entry);

            // Move to the next entry in the list
            entry = tempEntry;
        }

        // Set the bucket to NULL after freeing all entries
        HashTable[i] = NULL;
    }

    KeReleaseSpinLock(&HashTableLock, oldIrql);
}