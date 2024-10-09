#include <stdio.h>

#include "pch.h"
#include "minhook/include/MinHook.h"
#include "../Shared/common.h"
#include <winternl.h>  // needs to be on bottom?
#include "dllhelper.h"
#include "logging.h"


/******************* AllocateVirtualMemory ************************/

// Defines the prototype of the NtAllocateVirtualMemoryFunction
typedef DWORD(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

// Pointer to the trampoline function used to call the original NtAllocateVirtualMemory
pNtAllocateVirtualMemory pOriginalNtAllocateVirtualMemory = NULL;
DWORD NTAPI NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

//    int ret = swprintf_s(buf, DATA_BUFFER_SIZE, 
//        L"type:dll;time:%llu;krn_pid:%llu;func:AllocateVirtualMemory;pid:%p;base_addr:%p;zero:%#llx;size:%llu;type:%#lx;protect:%#lx",
//        time.QuadPart, (unsigned __int64) GetCurrentProcessId(), ProcessHandle, BaseAddress, ZeroBits, *RegionSize, AllocationType, Protect);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:AllocateVirtualMemory;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%p;", ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"base_addr:%p;", BaseAddress);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"zero:%#llx;", ZeroBits);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"size:%llu;", *RegionSize);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:%#lx;", AllocationType);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"protect:%#lx;", Protect);

    SendDllPipe(buf);

    // Broken atm?
    //LogMyStackTrace(&buf[ret], DATA_BUFFER_SIZE - ret);

    return pOriginalNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}


/******************* ProtectVirtualMemory ************************/


wchar_t* GetMemoryPermissions(wchar_t* buf, DWORD protection) {
    //char permissions[4] = "---"; // Initialize as "---"
    wcscpy_s(buf, 16, L"---");

    if (protection & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[0] = L'R'; // Readable
    }
    if (protection & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[1] = L'W'; // Writable
    }
    if (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[2] = L'X'; // Executable
    }
    buf[3] = L'\x00';

    return buf;
}

// Defines the prototype of the NtProtectVirtualMemoryFunction
typedef DWORD(NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PULONG NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
    );
pNtProtectVirtualMemory pOriginalNtProtectVirtualMemory = NULL;
DWORD NTAPI NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PULONG NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    
    wchar_t mem_perm[16] = L"";
    memset(mem_perm, 0, sizeof(mem_perm));
    GetMemoryPermissions(mem_perm, NewAccessProtection);

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE, 
    //    L"type:dll;time:%llu;krn_pid:%llu;func:ProtectVirtualMemory;pid:%p;base_addr:%p;size:%lu;new_access:%#lx;new_access_str:%ls",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), ProcessHandle,
    //    BaseAddress, *NumberOfBytesToProtect, NewAccessProtection, mem_perm);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:ProtectVirtualMemory;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%p;", ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"base_addr:%p;", BaseAddress);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"size:%lu;", *NumberOfBytesToProtect);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"new_access:%#lx;", NewAccessProtection);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"new_access_str:%ls;", mem_perm);

    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}


/******************* MapViewOfSection ************************/

typedef enum _SECTION_INHERIT {
    ViewShare = 1,   // Share the section.
    ViewUnmap = 2    // Unmap the section when the process terminates.
} SECTION_INHERIT;

// Defines the prototype of the NtMapViewOfSectionFunction
typedef DWORD(NTAPI* pNtMapViewOfSection)(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    DWORD           InheritDisposition,
    ULONG           AllocationType,
    ULONG           Protect
    );
pNtMapViewOfSection pOriginalNtMapViewOfSection = NULL;
DWORD NTAPI NtMapViewOfSection(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID*          BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    SECTION_INHERIT InheritDisposition,
    ULONG           AllocationType,
    ULONG           Protect
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    wchar_t mem_perm[16] = L"";
    memset(mem_perm, 0, sizeof(mem_perm));

    GetMemoryPermissions(mem_perm, Protect);

    // Check if pointers are not NULL before dereferencing
    LONGLONG sectionOffsetValue = (SectionOffset != NULL) ? SectionOffset->QuadPart : 0;
    SIZE_T viewSizeValue = (ViewSize != NULL) ? *ViewSize : 0;
    PVOID baseAddressValue = (BaseAddress != NULL) ? *BaseAddress : NULL;
    
    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:MapViewOfSection;section_handle:0x%p;process_handle:0x%p;base_address:0x%p;zero_bits:%llu;size:%llu;section_offset:%lld;view_size:%llu;inherit_disposition:%x;alloc_type:%x;protect:%x;protect_str:%ls",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(),
    //    SectionHandle, ProcessHandle, baseAddressValue, ZeroBits, CommitSize,
    //    sectionOffsetValue, viewSizeValue, InheritDisposition, AllocationType, Protect, mem_perm);

    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:MapViewOfSection;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"section_handle:0x%p;", SectionHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"process_handle:0x%p;", ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"base_address:0x%p;", baseAddressValue);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"zero_bits:%llu;", ZeroBits);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"size:%llu;", CommitSize);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"section_offset:%lld;", sectionOffsetValue);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"view_size:%llu;", viewSizeValue);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"inherit_disposition:%x;", InheritDisposition);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"alloc_type:%x;", AllocationType);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"protect:%x;", Protect);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"protect_str:%ls;", mem_perm);

    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
}


/******************* WriteVirtualMemory ************************/

// Defines the prototype of the NtWriteVirtualMemoryFunction
typedef DWORD(NTAPI* pNtWriteVirtualMemory)(
    HANDLE              ProcessHandle,
    PVOID               BaseAddress,
    PVOID               Buffer,
    ULONG               NumberOfBytesToWrite,
    PULONG              NumberOfBytesWritten
);
pNtWriteVirtualMemory pOriginalNtWriteVirtualMemory = NULL;
DWORD NTAPI NtWriteVirtualMemory(
    HANDLE              ProcessHandle,
    PVOID               BaseAddress,
    PVOID               Buffer,
    ULONG               NumberOfBytesToWrite,
    PULONG              NumberOfBytesWritten
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:WriteVirtualMemory;process_handle:0x%p;base_address:0x%p;buffer:0x%p;size:%lu",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(),
    //    ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite);

    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:WriteVirtualMemory;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"process_handle:0x%p;", ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"base_address:0x%p;", BaseAddress);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"buffer:0x%p;", Buffer);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"size:%lu;", NumberOfBytesToWrite);

    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}


/******************* ReadVirtualMemory ************************/

// Defines the prototype of the NtReadVirtualMemory function
typedef DWORD(NTAPI* pNtReadVirtualMemory)(
    HANDLE              ProcessHandle,
    PVOID               BaseAddress,
    PVOID               Buffer,
    ULONG               NumberOfBytesToRead,
    PULONG              NumberOfBytesRead
    );
pNtReadVirtualMemory pOriginalNtReadVirtualMemory = NULL;
DWORD NTAPI NtReadVirtualMemory(
    HANDLE              ProcessHandle,
    PVOID               BaseAddress,
    PVOID               Buffer,
    ULONG               NumberOfBytesToRead,
    PULONG              NumberOfBytesRead
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:ReadVirtualMemory;process_handle:0x%p;base_address:0x%p;buffer:0x%p;size:%lu",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(),
    //    ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead);

    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:ReadVirtualMemory;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"process_handle:0x%p;", ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"base_address:0x%p;", BaseAddress);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"buffer:0x%p;", Buffer);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"size:%lu;", NumberOfBytesToRead);

    SendDllPipe(buf);

    // Currently makes notepad.exe crash on save dialog open on win11.
    // And its a lot of data
    //LogMyStackTrace(&buf[ret], DATA_BUFFER_SIZE - ret);

    return pOriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}


/******************* NtSetContextThread ************************/

// Defines the prototype of the NtSetContextThreadFunction
typedef DWORD(NTAPI* pNtSetContextThread)(
    IN HANDLE               ThreadHandle,
    IN PCONTEXT             Context
    );
pNtSetContextThread pOriginalNtSetContextThread = NULL;
DWORD NTAPI NtSetContextThread(
    IN HANDLE               ThreadHandle,
    IN PCONTEXT             Context
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:SetContextThread;thread_handle:0x%p",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), ThreadHandle);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:SetContextThread;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"thread_handle:0x%p;", ThreadHandle);

    SendDllPipe(buf);
    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    return pOriginalNtSetContextThread(ThreadHandle, Context);
}


/******************* LdrLoadDll ************************/

typedef DWORD(NTAPI* pLdrLoadDll)(
    IN PWSTR            SearchPath          OPTIONAL,
    IN PULONG           DllCharacteristics  OPTIONAL,
    IN PUNICODE_STRING  DllName,
    OUT PVOID*          BaseAddress
    );
pLdrLoadDll pOriginalLdrLoadDll = NULL;
DWORD NTAPI LdrLoadDll(
    IN PWSTR            SearchPath          OPTIONAL,
    IN PULONG           DllCharacteristics  OPTIONAL,
    IN PUNICODE_STRING  DllName,
    OUT PVOID* BaseAddress
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    wchar_t wDllName[1024] = L"";  // Buffer for the decoded DllName
    wchar_t empty[32] = L"<broken>";        // Empty string in case SearchPath is NULL
    
    wchar_t* searchPath = empty;   // SearchPath seems to be 8 (the number 8, not a string) BROKEN
    UnicodeStringToWChar(DllName, wDllName, 1024);
    ULONG dllCharacteristics = (DllCharacteristics != NULL) ? *DllCharacteristics : 0;

   /* int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
        L"type:dll;time:%llu;krn_pid:%llu;func:LdrLoadDll;search_path:%ls;dll_characteristics:0x%lx;dll_name:%ls",
        time.QuadPart,
        (unsigned __int64)GetCurrentProcessId(),
        searchPath,
        dllCharacteristics,
        wDllName);*/

    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:LdrLoadDll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"search_path:%ls;", searchPath);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"dll_characteristics:0x%lx;", dllCharacteristics);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"dll_name:%ls;", wDllName);

    SendDllPipe(buf);
    return pOriginalLdrLoadDll(SearchPath, DllCharacteristics, DllName, BaseAddress);
}


/******************* LdrGetProcedureAddress ************************/

typedef DWORD(NTAPI* pLdrGetProcedureAddress)(
    IN HMODULE              ModuleHandle,
    IN PANSI_STRING         FunctionName,
    IN WORD                 Oridinal,
    OUT FARPROC* FunctionAddress
    );
pLdrGetProcedureAddress pOriginalLdrGetProcedureAddress = NULL;
DWORD NTAPI LdrGetProcedureAddress(
    IN HMODULE              ModuleHandle,
    IN PANSI_STRING         FunctionName,
    IN WORD                 Oridinal,
    OUT FARPROC* FunctionAddress
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    wchar_t wideFunctionName[1024] = L"";
    //UnicodeStringToWChar(FunctionName, wideFunctionName, 1024);

    if (FunctionName && FunctionName->Buffer) {
        // Convert ANSI string to wide string
        MultiByteToWideChar(CP_ACP, 0, FunctionName->Buffer, -1, wideFunctionName, 1024);
    }
    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:LdrGetProcedureAddress;module_handle:0x%p;function:%s;ordinal:0x%hx",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), ModuleHandle, wideFunctionName, Oridinal);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:LdrGetProcedureAddress;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"module_handle:0x%p;", ModuleHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"function:%s;", wideFunctionName);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"ordinal:0x%hx;", Oridinal);

    SendDllPipe(buf);

    return pOriginalLdrGetProcedureAddress(ModuleHandle, FunctionName, Oridinal, FunctionAddress);
}


/******************* NtQueueApcThread ************************/

typedef DWORD(NTAPI* pNtQueueApcThread)(
    IN HANDLE               ThreadHandle, 
    IN PIO_APC_ROUTINE      ApcRoutine,
    IN PVOID                ApcRoutineContext OPTIONAL,
    IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
    IN ULONG                ApcReserved OPTIONAL
    );
pNtQueueApcThread pOriginalNtQueueApcThread = NULL;
DWORD NTAPI NtQueueApcThread(
    IN HANDLE               ThreadHandle,    
    IN PIO_APC_ROUTINE      ApcRoutine,
    IN PVOID                ApcRoutineContext OPTIONAL,
    IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
    IN ULONG                ApcReserved OPTIONAL
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtQueueApcThread;thread_handle:0x%p",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), ThreadHandle);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtQueueApcThread;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"thread_handle:0x%p;", ThreadHandle);


    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtQueueApcThread(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
}


/******************* NtQueueApcThreadEx ************************/

typedef DWORD(NTAPI* pNtQueueApcThreadEx)(
    IN HANDLE               ThreadHandle,
    IN HANDLE               ApcThreadHandle,
    IN PVOID                ApcRoutine,
    IN PVOID                ApcArgument1,
    IN PVOID                ApcArgument2,
    IN PVOID                ApcArgument3
    );
pNtQueueApcThreadEx pOriginalNtQueueApcThreadEx = NULL;
DWORD NTAPI NtQueueApcThreadEx(
    IN HANDLE               ThreadHandle,
    IN HANDLE               ApcThreadHandle,
    IN PVOID                ApcRoutine,
    IN PVOID                ApcArgument1,
    IN PVOID                ApcArgument2,
    IN PVOID                ApcArgument3
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    OutputDebugString(L"A8");

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtQueueApcThreadEx;thread_handle:0x%p;apc_thread:0x%p;apc_routine:0x%p;arg1:0x%p;arg2:0x%p;arg3:0x%p",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), ThreadHandle, ApcThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtQueueApcThreadEx;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"thread_handle:0x%p;", ThreadHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"apc_thread:0x%p;", ApcThreadHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"apc_routine:0x%p;", ApcRoutine);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"arg1:0x%p;", ApcArgument1);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"arg2:0x%p;", ApcArgument2);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"arg3:0x%p;", ApcArgument3);

    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtQueueApcThreadEx(ThreadHandle, ApcThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}


/******************* NtCreateProcess ************************/

typedef DWORD(NTAPI* pNtCreateProcess)(
    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN HANDLE               ParentProcess,
    IN BOOLEAN              InheritObjectTable,
    IN HANDLE               SectionHandle,
    IN HANDLE               DebugPort,
    IN HANDLE               ExceptionPort
    );
pNtCreateProcess pOriginalNtCreateProcess = NULL;
DWORD NTAPI NtCreateProcess(
    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN HANDLE               ParentProcess,
    IN BOOLEAN              InheritObjectTable,
    IN HANDLE               SectionHandle,
    IN HANDLE               DebugPort,
    IN HANDLE               ExceptionPort
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    OutputDebugString(L"A9");

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtCreateProcess;process_handle:0x%p;access_mask:0x%x;parent_process:0x%p;inherit_table:%d",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), ProcessHandle, DesiredAccess, ParentProcess, InheritObjectTable);

    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtCreateProcess;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"process_handle:0x%p;", ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"access_mask:0x%x;", DesiredAccess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"parent_process:0x%p;", ParentProcess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"inherit_table:%d;", InheritObjectTable);

    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
}


/******************* NtCreateThreadEx ************************/

typedef DWORD(NTAPI* pNtCreateThreadEx)(
    OUT PHANDLE             ThreadHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN HANDLE               ProcessHandle,
    IN PVOID                StartRoutine,
    IN PVOID                Argument,
    IN ULONG                CreateFlags,
    IN ULONG_PTR            ZeroBits,
    IN SIZE_T               StackSize,
    IN SIZE_T               MaximumStackSize,
    IN PVOID                AttributeList
    );
pNtCreateThreadEx pOriginalNtCreateThreadEx = NULL;
DWORD NTAPI NtCreateThreadEx(
    OUT PHANDLE             ThreadHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN HANDLE               ProcessHandle,
    IN PVOID                StartRoutine,
    IN PVOID                Argument,
    IN ULONG                CreateFlags,
    IN ULONG_PTR            ZeroBits,
    IN SIZE_T               StackSize,
    IN SIZE_T               MaximumStackSize,
    IN PVOID                AttributeList
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtCreateThreadEx;thread_handle:0x%p;process_handle:0x%p;start_routine:0x%p;argument:0x%p",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), 
    //    ThreadHandle, ProcessHandle, StartRoutine, Argument);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtCreateThreadEx;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"thread_handle:0x%p;", ThreadHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"process_handle:0x%p;", ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"start_routine:0x%p;", StartRoutine);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"argument:0x%p;", Argument);

    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}


/******************* NtOpenProcess ************************/

typedef DWORD(NTAPI* pNtOpenProcess)(
    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN CLIENT_ID*           ClientId
    );
pNtOpenProcess pOriginalNtOpenProcess = NULL;
DWORD NTAPI NtOpenProcess(
    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN CLIENT_ID*           ClientId
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtOpenProcess;process_handle:0x%p;access_mask:0x%x;client_id_process:0x%p;client_id_thread:0x%p",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), ProcessHandle, DesiredAccess, ClientId->UniqueProcess, ClientId->UniqueThread);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtOpenProcess;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"process_handle:0x%p;", ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"access_mask:0x%x;", DesiredAccess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"client_id_process:0x%p;", ClientId->UniqueProcess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"client_id_thread:0x%p;", ClientId->UniqueThread);

    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}


/******************* NtLoadDriver ************************/

typedef DWORD(NTAPI* pNtLoadDriver)(
    IN PUNICODE_STRING      DriverServiceName
    );
pNtLoadDriver pOriginalNtLoadDriver = NULL;
DWORD NTAPI NtLoadDriver(
    IN PUNICODE_STRING      DriverServiceName
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    wchar_t wDriverServiceName[1024];

    OutputDebugString(L"A12");

    UnicodeStringToWChar(DriverServiceName, wDriverServiceName, 1024);

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtLoadDriver;driver_service_name:%ls",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), wDriverServiceName);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtLoadDriver;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"driver_service_name:%ls;", wDriverServiceName);

    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtLoadDriver(DriverServiceName);
}


/******************* NtCreateNamedPipeFile ************************/

typedef DWORD(NTAPI* pNtCreateNamedPipeFile)(
    OUT PHANDLE             NamedPipeFileHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    OUT PIO_STATUS_BLOCK    IoStatusBlock,
    IN ULONG                ShareAccess,
    IN ULONG                CreateDisposition,
    IN ULONG                CreateOptions,
    IN ULONG                NamedPipeType,
    IN ULONG                ReadMode,
    IN ULONG                CompletionMode,
    IN ULONG                MaximumInstances,
    IN ULONG                InboundQuota,
    IN ULONG                OutboundQuota,
    IN PLARGE_INTEGER       DefaultTimeout
    );
pNtCreateNamedPipeFile pOriginalNtCreateNamedPipeFile = NULL;
DWORD NTAPI NtCreateNamedPipeFile(
    OUT PHANDLE             NamedPipeFileHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    OUT PIO_STATUS_BLOCK    IoStatusBlock,
    IN ULONG                ShareAccess,
    IN ULONG                CreateDisposition,
    IN ULONG                CreateOptions,
    IN ULONG                NamedPipeType,
    IN ULONG                ReadMode,
    IN ULONG                CompletionMode,
    IN ULONG                MaximumInstances,
    IN ULONG                InboundQuota,
    IN ULONG                OutboundQuota,
    IN PLARGE_INTEGER       DefaultTimeout
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    OutputDebugString(L"A13");

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtCreateNamedPipeFile;pipe_handle:0x%p;access_mask:0x%x;share_access:0x%x;pipe_type:0x%x;read_mode:0x%x",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), NamedPipeFileHandle, DesiredAccess, ShareAccess, NamedPipeType, ReadMode);
    
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtCreateNamedPipeFile;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pipe_handle:0x%p;", NamedPipeFileHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"access_mask:0x%x;", DesiredAccess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"share_access:0x%x;", ShareAccess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pipe_type:0x%x;", NamedPipeType);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"read_mode:0x%x;", ReadMode);

    SendDllPipe(buf);
    return pOriginalNtCreateNamedPipeFile(NamedPipeFileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, NamedPipeType, ReadMode, CompletionMode, MaximumInstances, InboundQuota, OutboundQuota, DefaultTimeout);
}


/******************* NtOpenThread ************************/

typedef DWORD(NTAPI* pNtOpenThread)(
    OUT PHANDLE             ThreadHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN CLIENT_ID*           ClientId
    );
pNtOpenThread pOriginalNtOpenThread = NULL;
DWORD NTAPI NtOpenThread(
    OUT PHANDLE             ThreadHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN CLIENT_ID*           ClientId
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtOpenThread;thread_handle:0x%p;access_mask:0x%x;client_id_process:0x%p;client_id_thread:0x%p",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), ThreadHandle, DesiredAccess, ClientId->UniqueProcess, ClientId->UniqueThread);
    
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtOpenThread;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"thread_handle:0x%p;", ThreadHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"access_mask:0x%x;", DesiredAccess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"client_id_process:0x%p;", ClientId->UniqueProcess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"client_id_thread:0x%p;", ClientId->UniqueThread);

    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}


/******************* NtCreateSection ************************/

typedef DWORD(NTAPI* pNtCreateSection)(
    OUT PHANDLE             SectionHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN PLARGE_INTEGER       MaximumSize,
    IN ULONG                SectionPageProtection,
    IN ULONG                AllocationAttributes,
    IN HANDLE               FileHandle
    );
pNtCreateSection pOriginalNtCreateSection = NULL;
DWORD NTAPI NtCreateSection(
    OUT PHANDLE             SectionHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN PLARGE_INTEGER       MaximumSize,
    IN ULONG                SectionPageProtection,
    IN ULONG                AllocationAttributes,
    IN HANDLE               FileHandle
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtCreateSection;section_handle:0x%p;access_mask:0x%x;max_size:0x%p;page_protection:0x%x;alloc_attributes:0x%x;file_handle:0x%p",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), SectionHandle, DesiredAccess, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtCreateSection;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"section_handle:0x%p;", SectionHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"access_mask:0x%x;", DesiredAccess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"max_size:0x%p;", MaximumSize);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"page_protection:0x%x;", SectionPageProtection);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"alloc_attributes:0x%x;", AllocationAttributes);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"file_handle:0x%p;", FileHandle);
    
    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
}


/******************* NtCreateProcessEx ************************/

typedef DWORD(NTAPI* pNtCreateProcessEx)(
    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN HANDLE               ParentProcess,
    IN ULONG                Flags,
    IN HANDLE               SectionHandle,
    IN HANDLE               DebugPort,
    IN HANDLE               ExceptionPort,
    IN BOOLEAN              InJob
    );
pNtCreateProcessEx pOriginalNtCreateProcessEx = NULL;
DWORD NTAPI NtCreateProcessEx(
    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN HANDLE               ParentProcess,
    IN ULONG                Flags,
    IN HANDLE               SectionHandle,
    IN HANDLE               DebugPort,
    IN HANDLE               ExceptionPort,
    IN BOOLEAN              InJob
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    OutputDebugString(L"A16");

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtCreateProcessEx;process_handle:0x%p;parent_process:0x%p;flags:0x%lx;section_handle:0x%p;debug_port:0x%p;exception_port:0x%p;in_job:%d",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), ProcessHandle, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob);
    
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtCreateProcessEx;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"process_handle:0x%p;", ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"parent_process:0x%p;", ParentProcess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"flags:0x%lx;", Flags);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"section_handle:0x%p;", SectionHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"debug_port:0x%p;", DebugPort);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"exception_port:0x%p;", ExceptionPort);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"in_job:%d;", InJob);

    LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    SendDllPipe(buf);
    return pOriginalNtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob);
}


/******************* NtCreateEvent ************************/

typedef enum _EVENT_TYPE {
    NotificationEvent = 0,
    SynchronizationEvent = 1
} EVENT_TYPE;

typedef DWORD(NTAPI* pNtCreateEvent)(
    OUT PHANDLE             EventHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN EVENT_TYPE           EventType,
    IN BOOLEAN              InitialState
    );
pNtCreateEvent pOriginalNtCreateEvent = NULL;
DWORD NTAPI NtCreateEvent(
    OUT PHANDLE             EventHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN EVENT_TYPE           EventType,
    IN BOOLEAN              InitialState
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtCreateEvent;desired_access:0x%x;event_type:%d;initial_state:%d",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), DesiredAccess, EventType, InitialState);
    
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtCreateEvent;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"desired_access:0x%x;", DesiredAccess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"event_type:%d;", EventType);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"initial_state:%d;", InitialState);

    SendDllPipe(buf);
    return pOriginalNtCreateEvent(EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState);
}


/******************* NtCreateTimer ************************/

typedef enum _TIMER_TYPE {
    NotificationTimer,
    SynchronizationTimer
} TIMER_TYPE;

typedef DWORD(NTAPI* pNtCreateTimer)(
    OUT PHANDLE             TimerHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN TIMER_TYPE           TimerType
    );
pNtCreateTimer pOriginalNtCreateTimer = NULL;
DWORD NTAPI NtCreateTimer(
    OUT PHANDLE             TimerHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN TIMER_TYPE           TimerType
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtCreateTimer;desired_access:0x%x;timer_type:%d",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), DesiredAccess, TimerType);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtCreateTimer;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"desired_access:0x%x;", DesiredAccess);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"timer_type:%d;", TimerType);

    
    SendDllPipe(buf);
    return pOriginalNtCreateTimer(TimerHandle, DesiredAccess, ObjectAttributes, TimerType);
}


/******************* NtCreateTimer2 ************************/

typedef DWORD(NTAPI* pNtCreateTimer2)(
    OUT PHANDLE             TimerHandle,
    IN PVOID                Reserved1 OPTIONAL,
    IN PVOID                Reserved2 OPTIONAL,
    IN ULONG                Attributes,
    IN ACCESS_MASK          DesiredAccess
    );
pNtCreateTimer2 pOriginalNtCreateTimer2 = NULL;
DWORD NTAPI NtCreateTimer2(
    OUT PHANDLE             TimerHandle,
    IN PVOID                Reserved1 OPTIONAL,
    IN PVOID                Reserved2 OPTIONAL,
    IN ULONG                Attributes,
    IN ACCESS_MASK          DesiredAccess
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    //int ret = swprintf_s(buf, DATA_BUFFER_SIZE,
    //    L"type:dll;time:%llu;krn_pid:%llu;func:NtCreateTimer2;attributes:0x%lx;desired_access:0x%x",
    //    time.QuadPart, (unsigned __int64)GetCurrentProcessId(), Attributes, DesiredAccess);
    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu;", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%llu;", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%llu;", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:NtCreateTimer2;");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"attributes:0x%lx;", Attributes);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"desired_access:0x%x;", DesiredAccess);
    
    SendDllPipe(buf);
    return pOriginalNtCreateTimer2(TimerHandle, Reserved1, Reserved2, Attributes, DesiredAccess);
}


//----------------------------------------------------


// This function initializes the hooks via the MinHook library
DWORD WINAPI InitHooksThread(LPVOID param) {
    if (MH_Initialize() != MH_OK) {
        return -1;
    }
    MH_STATUS status;

    LOG_A(LOG_INFO, "Injected DLL Main thread started on pid %lu", GetCurrentProcessId());
    InitDllPipe();

    // Hooks
    MH_CreateHookApi(L"ntdll", "NtAllocateVirtualMemory", NtAllocateVirtualMemory, (LPVOID*)(&pOriginalNtAllocateVirtualMemory));
    MH_CreateHookApi(L"ntdll", "NtProtectVirtualMemory", NtProtectVirtualMemory, (LPVOID*)(&pOriginalNtProtectVirtualMemory));
    MH_CreateHookApi(L"ntdll", "NtMapViewOfSection", NtMapViewOfSection, (LPVOID*)(&pOriginalNtMapViewOfSection));
    MH_CreateHookApi(L"ntdll", "NtWriteVirtualMemory", NtWriteVirtualMemory, (LPVOID*)(&pOriginalNtWriteVirtualMemory));
    MH_CreateHookApi(L"ntdll", "NtReadVirtualMemory", NtReadVirtualMemory, (LPVOID*)(&pOriginalNtReadVirtualMemory));
    MH_CreateHookApi(L"ntdll", "NtSetContextThread", NtSetContextThread, (LPVOID*)(&pOriginalNtSetContextThread));
    MH_CreateHookApi(L"ntdll", "LdrLoadDll", LdrLoadDll, (LPVOID*)(&pOriginalLdrLoadDll));
    MH_CreateHookApi(L"ntdll", "LdrGetProcedureAddress", LdrGetProcedureAddress, (LPVOID*)(&pOriginalLdrGetProcedureAddress));
    MH_CreateHookApi(L"ntdll", "NtQueueApcThread", NtQueueApcThread, (LPVOID*)(&pOriginalNtQueueApcThread));
    MH_CreateHookApi(L"ntdll", "NtQueueApcThreadEx", NtQueueApcThreadEx, (LPVOID*)(&pOriginalNtQueueApcThreadEx));
    MH_CreateHookApi(L"ntdll", "NtCreateProcess", NtCreateProcess, (LPVOID*)(&pOriginalNtCreateProcess));
    MH_CreateHookApi(L"ntdll", "NtCreateThreadEx", NtCreateThreadEx, (LPVOID*)(&pOriginalNtCreateThreadEx));
    MH_CreateHookApi(L"ntdll", "NtOpenProcess", NtOpenProcess, (LPVOID*)(&pOriginalNtOpenProcess));
    MH_CreateHookApi(L"ntdll", "NtLoadDriver", NtLoadDriver, (LPVOID*)(&pOriginalNtLoadDriver));
    MH_CreateHookApi(L"ntdll", "NtCreateNamedPipeFile", NtCreateNamedPipeFile, (LPVOID*)(&pOriginalNtCreateNamedPipeFile));
    MH_CreateHookApi(L"ntdll", "NtOpenThread", NtOpenThread, (LPVOID*)(&pOriginalNtOpenThread));
    MH_CreateHookApi(L"ntdll", "NtCreateSection", NtCreateSection, (LPVOID*)(&pOriginalNtCreateSection));
    MH_CreateHookApi(L"ntdll", "NtCreateThreadEx", NtCreateThreadEx, (LPVOID*)(&pOriginalNtCreateThreadEx));
    MH_CreateHookApi(L"ntdll", "NtCreateProcessEx", NtCreateProcessEx, (LPVOID*)(&pOriginalNtCreateProcessEx));
    MH_CreateHookApi(L"ntdll", "NtCreateEvent", NtCreateEvent, (LPVOID*)(&pOriginalNtCreateEvent));
    MH_CreateHookApi(L"ntdll", "NtCreateTimer", NtCreateTimer, (LPVOID*)(&pOriginalNtCreateTimer));
    MH_CreateHookApi(L"ntdll", "NtCreateTimer2", NtCreateTimer2, (LPVOID*)(&pOriginalNtCreateTimer2));
    status = MH_EnableHook(MH_ALL_HOOKS);

    return status;
}


// Here is the DllMain of our DLL
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        // This DLL will not be loaded by any thread so we simply disable DLL_TRHEAD_ATTACH and DLL_THREAD_DETACH
        DisableThreadLibraryCalls(hModule);

        // Calling WinAPI32 functions from the DllMain is a very bad practice 
        // since it can basically lock the program loading the DLL
        // Microsoft recommends not using any functions here except a few one like 
        // CreateThread IF AND ONLY IF there is no need for synchronization
        // So basically we are creating a thread that will execute the InitHooksThread function 
        // thus allowing us hooking the NtAllocateVirtualMemory function
        HANDLE hThread = CreateThread(NULL, 0, InitHooksThread, NULL, 0, NULL);
        if (hThread != NULL) {
            CloseHandle(hThread);
        }
        /*hThread = CreateThread(NULL, 0, InitPipeThread, NULL, 0, NULL);
        if (hThread != NULL) {
            CloseHandle(hThread);
        }*/
        break;
    }
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}