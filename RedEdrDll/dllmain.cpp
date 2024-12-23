#include <Windows.h>
#include <stdio.h>
#include "../Shared/common.h"
#include <winternl.h>  // needs to be on bottom?
#include <dbghelp.h>

#include "dllhelper.h"
#include "logging.h"
#include "detours.h"
#include "utils.h"
#include "process_query.h" // to init it

// Config
BOOL skip_self_readprocess = TRUE;
BOOL skip_rw_r_virtualprotect = FALSE; // TODO
BOOL skip_nonzero_baseaddr_mapviewofsection = TRUE;

// Data
BOOL HooksInitialized = FALSE;


void UnicodeStringToWChar(const UNICODE_STRING* ustr, wchar_t* dest, size_t destSize)
{
    if (!ustr || !dest || destSize == 0) {
        return;  // Invalid arguments or destination size is zero
    }

    // Ensure that the source UNICODE_STRING is valid
    if (ustr->Length == 0 || ustr->Buffer == NULL) {
        dest[0] = L'\0';  // Set dest to an empty string
        return;
    }

    // Get the number of characters to copy (Length is in bytes, so divide by sizeof(WCHAR))
    size_t numChars = ustr->Length / sizeof(WCHAR);

    // Copy length should be the smaller of the available characters or the destination size minus 1 (for null terminator)
    size_t copyLength = (numChars < destSize - 1) ? numChars : destSize - 1;

    // Use wcsncpy_s to safely copy the string
    wcsncpy_s(dest, destSize, ustr->Buffer, copyLength);

    // Ensure the destination string is null-terminated
    dest[copyLength] = L'\0';
}


/******************* AllocateVirtualMemory ************************/

typedef NTSTATUS(NTAPI* t_NtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );
t_NtAllocateVirtualMemory Real_NtAllocateVirtualMemory = NULL;

static NTSTATUS NTAPI Catch_NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (!HooksInitialized) { // dont log our own hooking
        return Real_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
    }

    // Request address
    PVOID addr_req = (BaseAddress != NULL) ? *BaseAddress : NULL;
    SIZE_T size_req = (RegionSize != NULL) ? *RegionSize : NULL;

    // Execute real function
    NTSTATUS ret = Real_NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

    // Real address
    PVOID addr = (BaseAddress != NULL) ? *BaseAddress : NULL;
    SIZE_T size = (RegionSize != NULL) ? *RegionSize : NULL;

    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtAllocateVirtualMemory\",");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"handle\":%lld,", (long long)ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"addr\":%llu,", addr);
    if (addr_req != NULL && addr_req != addr) {
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"addr_req\":%llu,", addr_req);
    }
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"zero\":%llu,", ZeroBits);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"size\":%llu,", size);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"size_req\":%llu,", size_req);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"alloc_type\":%lu,", AllocationType);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"protect\":\"%s\",", getMemoryRegionProtect(Protect));
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"return\":%ld", ret);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");

    // BROKEN for some reason. Do not attempt to enable it again.
    //offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);

    SendDllPipe(buf);

    return ret;
}

/******************* FreeVirtualMemory ************************/

typedef NTSTATUS(NTAPI* t_NtFreeVirtualMemory)(
    IN HANDLE       ProcessHandle,
    IN PVOID*       BaseAddress,
    IN OUT PULONG   RegionSize,
    IN ULONG        FreeType
    );
t_NtFreeVirtualMemory Real_NtFreeVirtualMemory = NULL;

static NTSTATUS NTAPI Catch_NtFreeVirtualMemory(
    IN HANDLE       ProcessHandle,
    IN PVOID*       BaseAddress,
    IN OUT PULONG   RegionSize,
    IN ULONG        FreeType)
{
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (!HooksInitialized) { // dont log our own hooking
        return Real_NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);
    }

    // Request address
    PVOID addr_req = (BaseAddress != NULL) ? *BaseAddress : NULL;
    ULONG size_req = (RegionSize != NULL) ? *RegionSize : NULL;

    // Execute real function
    NTSTATUS ret = Real_NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType);

    // Real address
    PVOID addr = (BaseAddress != NULL) ? *BaseAddress : NULL;
    ULONG size = (RegionSize != NULL) ? *RegionSize : NULL;

    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtFreeVirtualMemory\",");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"handle\":%lld,", (long long)ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"addr\":%llu,", addr);
    if (addr_req != NULL && addr_req != addr) {
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"addr_req\":%llu,", addr_req);
    }
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"size\":%llu,", size);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"size_req\":%lu,", size_req);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"free_type\":%lx,", FreeType);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"return\":%ld", ret);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");

    SendDllPipe(buf);

    return ret;
}


/******************* ProtectVirtualMemory ************************/

typedef NTSTATUS(NTAPI* t_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PULONG NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
    );
t_NtProtectVirtualMemory Real_NtProtectVirtualMemory = NULL;

static NTSTATUS NTAPI Catch_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PULONG NumberOfBytesToProtect,
    ULONG NewAccessProtection,
    PULONG OldAccessProtection
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (!HooksInitialized) { // dont log our own hooking
        return Real_NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
    }

    // Request address
    PVOID addr_req = (BaseAddress != NULL) ? *BaseAddress : NULL;

    // Exec
    NTSTATUS ret = Real_NtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);

    // Real address
    PVOID addr = (BaseAddress != NULL) ? *BaseAddress : NULL;

    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtProtectVirtualMemory\",");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"handle\":%lld,", (long long)ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"addr\":%llu,", addr);
    if (addr_req != NULL && addr_req != addr) {
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"addr_req\":%llu,", addr);
    }
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"size\":%lu,", *NumberOfBytesToProtect);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"protect\":\"%s\",", getMemoryRegionProtect(NewAccessProtection));
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"return\":%ld,", ret);
    offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
    SendDllPipe(buf);
    return ret;
}


/******************* MapViewOfSection ************************/

typedef enum _SECTION_INHERIT {
    ViewShare = 1,   // Share the section.
    ViewUnmap = 2    // Unmap the section when the process terminates.
} SECTION_INHERIT;

// Defines the prototype of the NtMapViewOfSectionFunction
typedef NTSTATUS(NTAPI* t_NtMapViewOfSection)(
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
t_NtMapViewOfSection Real_NtMapViewOfSection = NULL;
NTSTATUS NTAPI Catch_NtMapViewOfSection(
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

    if (!HooksInitialized) { // dont log our own hooking
        return Real_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);
    }

    // Check if pointers are not NULL before dereferencing
    LONGLONG sectionOffsetValue = (SectionOffset != NULL) ? SectionOffset->QuadPart : 0;
    SIZE_T viewSizeValue = (ViewSize != NULL) ? *ViewSize : 0;
    PVOID baseAddressValue = (BaseAddress != NULL) ? *BaseAddress : NULL;

    NTSTATUS ret = Real_NtMapViewOfSection(SectionHandle, ProcessHandle, BaseAddress, ZeroBits, CommitSize, SectionOffset, ViewSize, InheritDisposition, AllocationType, Protect);

    int offset = 0;
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtMapViewOfSection\",");
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"section_handle\":%lld,", SectionHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"handle\":%lld,", (long long)ProcessHandle);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"base_address\":%llu,", baseAddressValue);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"zero_bits\":%llu,", ZeroBits);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"size\":%llu,", CommitSize);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"section_offset\":%lld,", sectionOffsetValue);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"view_size\":%llu,", viewSizeValue);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"inherit_disposition\":%x,", InheritDisposition);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"alloc_type\":%x,", AllocationType);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"protect\":\"%s\",", getMemoryRegionProtect(Protect));
    offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
    offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");

    SendDllPipe(buf);
    return ret;
}


/******************* WriteVirtualMemory ************************/

// Defines the prototype of the NtWriteVirtualMemoryFunction
typedef NTSTATUS(NTAPI* t_NtWriteVirtualMemory)(
    HANDLE              ProcessHandle,
    PVOID               BaseAddress,
    PVOID               Buffer,
    ULONG               NumberOfBytesToWrite,
    PULONG              NumberOfBytesWritten
    );
t_NtWriteVirtualMemory Real_NtWriteVirtualMemory = NULL;
NTSTATUS NTAPI Catch_NtWriteVirtualMemory(
    HANDLE              ProcessHandle,
    PVOID               BaseAddress,
    PVOID               Buffer,
    ULONG               NumberOfBytesToWrite,
    PULONG              NumberOfBytesWritten
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (HooksInitialized) { // dont log our own hooking
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtWriteVirtualMemory\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"handle\":%lld,", (long long)ProcessHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"base_address\":%llu,", BaseAddress);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"buffer\":%llu,", Buffer);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"size\":%lu,", NumberOfBytesToWrite);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        
        SendDllPipe(buf);
    }
    return Real_NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}


/******************* ReadVirtualMemory ************************/

// Defines the prototype of the NtReadVirtualMemory function
typedef NTSTATUS(NTAPI* pNtReadVirtualMemory)(
    HANDLE              ProcessHandle,
    PVOID               BaseAddress,
    PVOID               Buffer,
    ULONG               NumberOfBytesToRead,
    PULONG              NumberOfBytesRead
    );
pNtReadVirtualMemory Real_NtReadVirtualMemory = NULL;
NTSTATUS NTAPI Catch_NtReadVirtualMemory(
    HANDLE              ProcessHandle,
    PVOID               BaseAddress,
    PVOID               Buffer,
    ULONG               NumberOfBytesToRead,
    PULONG              NumberOfBytesRead
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (HooksInitialized) { // dont log our own hooking
        if (!skip_self_readprocess || ProcessHandle != (HANDLE)-1) {
            int offset = 0;
            offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
            offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
            offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\"k:%llu,", time.QuadPart);
            offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
            offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
            offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtReadVirtualMemory\",");
            offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"handle\":%lld,", (long long)ProcessHandle);
            offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"base_address\":%llu,", BaseAddress);
            offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"buffer\":%llu,", Buffer);
            offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"size\":%lu", NumberOfBytesToRead);
            offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
            SendDllPipe(buf);
        }

        // Currently makes notepad.exe crash on save dialog open on win11.
        // And its a lot of data
        //offset += LogMyStackTrace(&buf[ret], DATA_BUFFER_SIZE - ret);
    }

    return Real_NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesRead);
}


/******************* NtSetContextThread ************************/
/*
// Defines the prototype of the NtSetContextThreadFunction
typedef NTSTATUS(NTAPI* pNtSetContextThread)(
    IN HANDLE               ThreadHandle,
    IN PCONTEXT             Context
    );
pNtSetContextThread Real_NtSetContextThread = NULL;
NTSTATUS NTAPI Catch_NtSetContextThread(
    IN HANDLE               ThreadHandle,
    IN PCONTEXT             Context
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (HooksInitialized) { // dont log our own hooking
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll,");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:SetContextThread,");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"thread_handle:%llu,", ThreadHandle);

        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        SendDllPipe(buf);
    }

    return Real_NtSetContextThread(ThreadHandle, Context);
}
*/

/******************* LdrLoadDll ************************/

typedef NTSTATUS(NTAPI* pLdrLoadDll)(
    IN PWSTR            SearchPath          OPTIONAL,
    IN PULONG           DllCharacteristics  OPTIONAL,
    IN PUNICODE_STRING  DllName,
    OUT PVOID*          BaseAddress
    );
pLdrLoadDll Real_LdrLoadDll = NULL;
NTSTATUS NTAPI Catch_LdrLoadDll(
    IN PWSTR            SearchPath          OPTIONAL,
    IN PULONG           DllCharacteristics  OPTIONAL,
    IN PUNICODE_STRING  DllName,
    OUT PVOID* BaseAddress
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    wchar_t wDllName[1024] = L"";  // Buffer for the decoded DllName
    wchar_t empty[32] = L"<broken>";        // Empty string in case SearchPath is NULL

    if (HooksInitialized) { // dont log our own hooking
        wchar_t* searchPath = empty;   // SearchPath seems to be 8 (the number 8, not a string) BROKEN
        UnicodeStringToWChar(DllName, wDllName, 1024);
        ULONG dllCharacteristics = (DllCharacteristics != NULL) ? *DllCharacteristics : 0;

        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"LdrLoadDll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"search_path\":\"%ls\",", searchPath);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"dll_characteristics\":%lu,", dllCharacteristics);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"dll_name\":\"%ls\",", wDllName);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");

        SendDllPipe(buf);
    }
    return Real_LdrLoadDll(SearchPath, DllCharacteristics, DllName, BaseAddress);
}


/******************* LdrGetProcedureAddress ************************/

typedef NTSTATUS(NTAPI* pLdrGetProcedureAddress)(
    IN HMODULE              ModuleHandle,
    IN PANSI_STRING         FunctionName,
    IN WORD                 Oridinal,
    OUT FARPROC* FunctionAddress
    );
pLdrGetProcedureAddress Real_LdrGetProcedureAddress = NULL;
NTSTATUS NTAPI Catch_LdrGetProcedureAddress(
    IN HMODULE              ModuleHandle,
    IN PANSI_STRING         FunctionName,
    IN WORD                 Oridinal,
    OUT FARPROC* FunctionAddress
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    wchar_t wideFunctionName[1024] = L"";

    if (HooksInitialized) { // dont log our own hooking
        //UnicodeStringToWChar(FunctionName, wideFunctionName, 1024);

        if (FunctionName && FunctionName->Buffer) {
            // Convert ANSI string to wide string
            MultiByteToWideChar(CP_ACP, 0, FunctionName->Buffer, -1, wideFunctionName, 1024);
        }

        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"LdrGetProcedureAddress\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"module_handle\":%lld,", ModuleHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"function\":\"%s\",", wideFunctionName);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"ordinal\":%u", Oridinal);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");

        SendDllPipe(buf);
    }

    return Real_LdrGetProcedureAddress(ModuleHandle, FunctionName, Oridinal, FunctionAddress);
}


/******************* NtQueueApcThread ************************/

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    IN HANDLE               ThreadHandle,
    IN PIO_APC_ROUTINE      ApcRoutine,
    IN PVOID                ApcRoutineContext OPTIONAL,
    IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
    IN ULONG                ApcReserved OPTIONAL
    );
pNtQueueApcThread Real_NtQueueApcThread = NULL;
NTSTATUS NTAPI Catch_NtQueueApcThread(
    IN HANDLE               ThreadHandle,
    IN PIO_APC_ROUTINE      ApcRoutine,
    IN PVOID                ApcRoutineContext OPTIONAL,
    IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
    IN ULONG                ApcReserved OPTIONAL
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (HooksInitialized) { // dont log our own hooking
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtQueueApcThread\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"thread_handle\":%lld,", ThreadHandle);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        
        SendDllPipe(buf);
    }
    return Real_NtQueueApcThread(ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
}


/******************* NtQueueApcThreadEx ************************/

typedef NTSTATUS(NTAPI* pNtQueueApcThreadEx)(
    IN HANDLE               ThreadHandle,
    IN HANDLE               ApcThreadHandle,
    IN PVOID                ApcRoutine,
    IN PVOID                ApcArgument1,
    IN PVOID                ApcArgument2,
    IN PVOID                ApcArgument3
    );
pNtQueueApcThreadEx Real_NtQueueApcThreadEx = NULL;
NTSTATUS NTAPI Catch_NtQueueApcThreadEx(
    IN HANDLE               ThreadHandle,
    IN HANDLE               ApcThreadHandle,
    IN PVOID                ApcRoutine,
    IN PVOID                ApcArgument1,
    IN PVOID                ApcArgument2,
    IN PVOID                ApcArgument3
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (HooksInitialized) { // dont log our own hooking
        OutputDebugString(L"A8");
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtQueueApcThreadEx\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"thread_handle\":%lld,", ThreadHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"apc_thread\":%llu,", ApcThreadHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"apc_routine\":%llu,", ApcRoutine);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"arg1\":%llu,", ApcArgument1);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"arg2\":%llu,", ApcArgument2);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"arg3\":%llu,", ApcArgument3);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        
        SendDllPipe(buf);
    }
    return Real_NtQueueApcThreadEx(ThreadHandle, ApcThreadHandle, ApcRoutine, ApcArgument1, ApcArgument2, ApcArgument3);
}


/******************* NtCreateProcess ************************/

typedef NTSTATUS(NTAPI* pNtCreateProcess)(
    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN HANDLE               ParentProcess,
    IN BOOLEAN              InheritObjectTable,
    IN HANDLE               SectionHandle,
    IN HANDLE               DebugPort,
    IN HANDLE               ExceptionPort
    );
pNtCreateProcess Real_NtCreateProcess = NULL;
NTSTATUS NTAPI Catch_NtCreateProcess(
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

    if (HooksInitialized) { // dont log our own hooking
        OutputDebugString(L"A9");
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtCreateProcess\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"handle\":%lld,", (long long)ProcessHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"access_mask\":%u,", DesiredAccess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"parent_process\":%llu,", ParentProcess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"inherit_table\":%d,", InheritObjectTable);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        SendDllPipe(buf);
    }
    return Real_NtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
}


/******************* NtCreateThread ************************/

typedef NTSTATUS(NTAPI* pNtCreateThread)(
    OUT PHANDLE             ThreadHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN HANDLE               ProcessHandle,
    OUT CLIENT_ID* ClientId,
    IN PCONTEXT             ThreadContext,
    IN PVOID         InitialTeb,
    IN BOOLEAN              CreateSuspended
    );
pNtCreateThread Real_NtCreateThread = NULL;
NTSTATUS NTAPI Catch_NtCreateThread(
    OUT PHANDLE             ThreadHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN HANDLE               ProcessHandle,
    OUT CLIENT_ID* ClientId,
    IN PCONTEXT             ThreadContext,
    IN PVOID         InitialTeb,
    IN BOOLEAN              CreateSuspended
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    NTSTATUS ret = Real_NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
    if (HooksInitialized) { // dont log our own hooking
        HANDLE rUniqueProcess = (ClientId != NULL) ? ClientId->UniqueProcess : NULL;
        HANDLE rUniqueThread = (ClientId != NULL) ? ClientId->UniqueThread : NULL;
        HANDLE rThreadHandle = (ThreadHandle != NULL) ? *ThreadHandle : NULL;

        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtCreateThread\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"thread_handle\":%lld,", rThreadHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"handle\":%lld,", (long long)ProcessHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"suspended\":%llu,", CreateSuspended);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"unique_process\":%llu,", rUniqueProcess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"unique_thread\":%llu,", rUniqueThread);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        SendDllPipe(buf);
    }
    return ret;
}


/******************* NtCreateThreadEx ************************/

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
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
pNtCreateThreadEx Real_NtCreateThreadEx = NULL;
NTSTATUS NTAPI Catch_NtCreateThreadEx(
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

    NTSTATUS ret = Real_NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
    if (HooksInitialized) { // dont log our own hooking
        HANDLE rThreadHandle = (ThreadHandle != NULL) ? *ThreadHandle : NULL;

        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtCreateThreadEx\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"thread_handle\":%lld,", rThreadHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"handle\":%lld,", (long long)ProcessHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"start_routine\":%llu,", StartRoutine);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"argument\":%llu,", Argument);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        SendDllPipe(buf);
    }
    return ret;
}


/******************* NtOpenProcess ************************/

typedef NTSTATUS(NTAPI* pNtOpenProcess)(
    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN CLIENT_ID* ClientId
    );
pNtOpenProcess Real_NtOpenProcess = NULL;
NTSTATUS NTAPI Catch_NtOpenProcess(
    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN CLIENT_ID* ClientId
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (HooksInitialized) { // dont log our own hooking
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtOpenProcess\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"handle\":%lld,", (long long)ProcessHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"access_mask\":%lu,", DesiredAccess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"client_id_process\":%llu,", ClientId->UniqueProcess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"client_id_thread\":%llu,", ClientId->UniqueThread);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        SendDllPipe(buf);
    }
    return Real_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}


/******************* NtLoadDriver ************************/

typedef NTSTATUS(NTAPI* pNtLoadDriver)(
    IN PUNICODE_STRING      DriverServiceName
    );
pNtLoadDriver Real_NtLoadDriver = NULL;
NTSTATUS NTAPI Catch_NtLoadDriver(
    IN PUNICODE_STRING      DriverServiceName
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    wchar_t wDriverServiceName[1024];

    if (HooksInitialized) { // dont log our own hooking
        OutputDebugString(L"A12");
        UnicodeStringToWChar(DriverServiceName, wDriverServiceName, 1024);

        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtLoadDriver;\"");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"driver_service_name\":\"%ls\",", wDriverServiceName);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        SendDllPipe(buf);
    }
    return Real_NtLoadDriver(DriverServiceName);
}


/******************* NtCreateNamedPipeFile ************************/

typedef NTSTATUS(NTAPI* pNtCreateNamedPipeFile)(
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
pNtCreateNamedPipeFile Real_NtCreateNamedPipeFile = NULL;
NTSTATUS NTAPI Catch_NtCreateNamedPipeFile(
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
    if (HooksInitialized) { // dont log our own hooking
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtCreateNamedPipeFile\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pipe_handle\":%lld,", NamedPipeFileHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"access_mask\":%lu,", DesiredAccess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"share_access\":%lu,", ShareAccess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pipe_type\":%lu,", NamedPipeType);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"read_mode\":%lu", ReadMode);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        SendDllPipe(buf);
    }
    return Real_NtCreateNamedPipeFile(NamedPipeFileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition, CreateOptions, NamedPipeType, ReadMode, CompletionMode, MaximumInstances, InboundQuota, OutboundQuota, DefaultTimeout);
}


/******************* NtOpenThread ************************/

typedef NTSTATUS(NTAPI* pNtOpenThread)(
    OUT PHANDLE             ThreadHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN CLIENT_ID*           ClientId
    );
pNtOpenThread Real_NtOpenThread = NULL;
NTSTATUS NTAPI Catch_NtOpenThread(
    OUT PHANDLE             ThreadHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN CLIENT_ID*           ClientId
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    if (HooksInitialized) { // dont log our own hooking
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtOpenThread\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"thread_handle\":%lld,", ThreadHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"access_mask\":%lu,", DesiredAccess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"client_id_process\":%llu,", ClientId->UniqueProcess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"client_id_thread\":%llu,", ClientId->UniqueThread);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        SendDllPipe(buf);
    }
    return Real_NtOpenThread(ThreadHandle, DesiredAccess, ObjectAttributes, ClientId);
}


/******************* NtCreateSection ************************/

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    OUT PHANDLE             SectionHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN PLARGE_INTEGER       MaximumSize,
    IN ULONG                SectionPageProtection,
    IN ULONG                AllocationAttributes,
    IN HANDLE               FileHandle
    );
pNtCreateSection Real_NtCreateSection = NULL;
NTSTATUS NTAPI Catch_NtCreateSection(
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

    NTSTATUS ret = Real_NtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);

    if (HooksInitialized) { // dont log our own hooking
        HANDLE SectionHandleValue = (SectionHandle != NULL) ? *SectionHandle : NULL;

        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtCreateSection\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"section_handle\":%llu,", (unsigned long long) SectionHandleValue);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"access_mask\":%lu,", DesiredAccess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"max_size\":%llu,", MaximumSize);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"page_protection\":%lu,", SectionPageProtection);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"alloc_attributes\":%lu,", AllocationAttributes);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"file_handle\":%llu,", (unsigned long long) FileHandle);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        SendDllPipe(buf);
    }
    return ret;
}


/******************* NtCreateProcessEx ************************/

typedef NTSTATUS(NTAPI* pNtCreateProcessEx)(
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
pNtCreateProcessEx Real_NtCreateProcessEx = NULL;
NTSTATUS NTAPI Catch_NtCreateProcessEx(
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

    if (HooksInitialized) { // dont log our own hooking
        OutputDebugString(L"A16");

        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtCreateProcessEx\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"handle\":%lld,", (long long) ProcessHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"parent_process\":%llu,", (unsigned long long) ParentProcess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"flags\":%lu,", Flags);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"section_handle\":%llu,", (unsigned long long) SectionHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"debug_port\":%llu,", (unsigned long long) DebugPort);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"exception_port\":%llu,", (unsigned long long) ExceptionPort);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"in_job\":%d,", InJob);
        offset += LogMyStackTrace(&buf[offset], DATA_BUFFER_SIZE - offset);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        SendDllPipe(buf);
    }
    return Real_NtCreateProcessEx(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob);
}


/******************* NtCreateEvent ************************/

typedef enum _EVENT_TYPE {
    NotificationEvent = 0,
    SynchronizationEvent = 1
} EVENT_TYPE;

typedef NTSTATUS(NTAPI* pNtCreateEvent)(
    OUT PHANDLE             EventHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN EVENT_TYPE           EventType,
    IN BOOLEAN              InitialState
    );
pNtCreateEvent Real_NtCreateEvent = NULL;
NTSTATUS NTAPI Catch_NtCreateEvent(
    OUT PHANDLE             EventHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN EVENT_TYPE           EventType,
    IN BOOLEAN              InitialState
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (HooksInitialized) { // dont log our own hooking
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtCreateEvent\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"desired_access\":%lu,", DesiredAccess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"event_type\":%d,", EventType);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"initial_state\":%d", InitialState);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");

        SendDllPipe(buf);
    }
    return Real_NtCreateEvent(EventHandle, DesiredAccess, ObjectAttributes, EventType, InitialState);
}


/******************* NtCreateTimer ************************/

typedef enum _TIMER_TYPE {
    NotificationTimer,
    SynchronizationTimer
} TIMER_TYPE;

typedef NTSTATUS(NTAPI* pNtCreateTimer)(
    OUT PHANDLE             TimerHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN TIMER_TYPE           TimerType
    );
pNtCreateTimer Real_NtCreateTimer = NULL;
NTSTATUS NTAPI Catch_NtCreateTimer(
    OUT PHANDLE             TimerHandle,
    IN ACCESS_MASK          DesiredAccess,
    IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
    IN TIMER_TYPE           TimerType
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (HooksInitialized) { // dont log our own hooking
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtCreateTimer\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"desired_access\":%lu,", DesiredAccess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"timer_type\":%d", TimerType);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");

        SendDllPipe(buf);
    }
    return Real_NtCreateTimer(TimerHandle, DesiredAccess, ObjectAttributes, TimerType);
}


/******************* NtCreateTimer2 ************************/

typedef NTSTATUS(NTAPI* pNtCreateTimer2)(
    OUT PHANDLE             TimerHandle,
    IN PVOID                Reserved1 OPTIONAL,
    IN PVOID                Reserved2 OPTIONAL,
    IN ULONG                Attributes,
    IN ACCESS_MASK          DesiredAccess
    );
pNtCreateTimer2 Real_NtCreateTimer2 = NULL;
NTSTATUS NTAPI Catch_NtCreateTimer2(
    OUT PHANDLE             TimerHandle,
    IN PVOID                Reserved1 OPTIONAL,
    IN PVOID                Reserved2 OPTIONAL,
    IN ULONG                Attributes,
    IN ACCESS_MASK          DesiredAccess
) {
    LARGE_INTEGER time = get_time();
    wchar_t buf[DATA_BUFFER_SIZE] = L"";

    if (HooksInitialized) { // dont log our own hooking
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", (DWORD)GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", (DWORD)GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtCreateTimer2\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"attributes\":%lu,", Attributes);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"desired_access\":%lu", DesiredAccess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");

        SendDllPipe(buf);
    }
    return Real_NtCreateTimer2(TimerHandle, Reserved1, Reserved2, Attributes, DesiredAccess);
}


/******************* CreateRemoteThread ************************/
/*
typedef NTSTATUS(NTAPI* pNtCreateRemoteThread)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
    );
pNtCreateRemoteThread Real_NtCreateRemoteThread = nullptr;
NTSTATUS NTAPI Catch_NtCreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
) {
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    LARGE_INTEGER time = get_time();

    if (HooksInitialized) { // Avoid logging internal operations
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll,");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%lu,", GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%lu,", GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:CreateRemoteThread,");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"handle:%llu,", hProcess);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"start_address:%lu", lpStartAddress);

        SendDllPipe(buf);
    }

    return Real_NtCreateRemoteThread(
        hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId
    );
}
*/

/******************* QueryInformationThread ************************/
/*
typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength,
    PULONG          ReturnLength
);
pNtQueryInformationThread Real_NtQueryInformationThread = nullptr;
NTSTATUS NTAPI Hooked_NtQueryInformationThread (
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength,
    PULONG          ReturnLength
) {
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    LARGE_INTEGER time = get_time();

    if (HooksInitialized) { // Avoid logging internal operations
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll,");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%lu,", GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%lu,", GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:QueryInformationThread,");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"thread_handle:%llu,", ThreadHandle);

        SendDllPipe(buf);
    }

    return Real_NtQueryInformationThread(
        ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength
    );
}
*/

/******************* SetInformationThread ************************/

/*
typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength
);
pNtSetInformationThread Real_NtSetInformationThread = nullptr;
NTSTATUS NTAPI Hooked_NtSetInformationThread(
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength
) {
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    LARGE_INTEGER time = get_time();

    if (HooksInitialized) { // Avoid logging internal operations
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"type:dll,");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"time:%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"pid:%lu,", GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"tid:%lu,", GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"func:SetInformationThread,");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"thread_handle:%llu,", ThreadHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"ThreadInformationClass:%lu,", ThreadInformationClass);

        SendDllPipe(buf);
    }

    return Real_NtSetInformationThread(
        ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength
    );
}
*/


/******************* NtResumeThread ************************/

typedef NTSTATUS(NTAPI* pNtResumeThread)(
    HANDLE ThreadHandle,
    PULONG SuspendCount OPTIONAL
    );
pNtResumeThread Real_NtResumeThread = nullptr;
NTSTATUS NTAPI Catch_NtResumeThread(
    HANDLE ThreadHandle,
    PULONG SuspendCount OPTIONAL
) {
    wchar_t buf[DATA_BUFFER_SIZE] = L"";
    LARGE_INTEGER time = get_time();

    if (HooksInitialized) { // Avoid logging internal operations
        int offset = 0;
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"{");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"type\":\"dll\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"time\":%llu,", time.QuadPart);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"pid\":%lu,", GetCurrentProcessId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"tid\":%lu,", GetCurrentThreadId());
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"func\":\"NtResumeThread\",");
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"\"thread_handle\":%llu", (unsigned long long)ThreadHandle);
        offset += swprintf_s(buf + offset, DATA_BUFFER_SIZE - offset, L"}");
        SendDllPipe(buf);
    }

    return Real_NtResumeThread(
        ThreadHandle, SuspendCount
    );
}

//----------------------------------------------------

// This function initializes the hooks via the MinHook library
DWORD WINAPI InitHooksThread(LPVOID param) {
    LONG error;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    wchar_t start_str[1024] = { 0 };
    wchar_t stop_str[1024] = { 0 };

    swprintf(start_str, 1024, L"{\"type\":\"dll\",\"func\":\"hooking_start\",\"pid\":%lu,\"tid\":%lu}",
        (DWORD)GetCurrentProcessId(), (DWORD)GetCurrentThreadId());
    swprintf(stop_str, 1024, L"{\"type\":\"dll\",\"func\":\"hooking_finished\",\"pid\":%lu,\"tid\":%lu}",
        (DWORD)GetCurrentProcessId(), (DWORD)GetCurrentThreadId());

    LOG_A(LOG_INFO, "Injected DLL Detours Main thread started on pid %lu  threadid %lu",
        GetCurrentProcessId(), GetCurrentThreadId());
    InitProcessQuery();
    InitDllPipe();
    SendDllPipe(start_str);

    // All the original methods

    // NOTE: Do be VERY CAREFUL enabling these
    //       Just uncommenting the variable will break the callstack 
    //       (e.g. with a nonexisting function as parameter)
    //Real_LdrLoadDll = (pLdrLoadDll)DetourFindFunction("ntdll.dll", "LdrLoadDll");
    Real_LdrGetProcedureAddress = (pLdrGetProcedureAddress)DetourFindFunction("ntdll.dll", "LdrGetProcedureAddress");
    Real_NtQueueApcThread = (pNtQueueApcThread)DetourFindFunction("ntdll.dll", "NtQueueApcThread");
    Real_NtQueueApcThreadEx = (pNtQueueApcThreadEx)DetourFindFunction("ntdll.dll", "NtQueueApcThreadEx");
    Real_NtCreateProcess = (pNtCreateProcess)DetourFindFunction("ntdll.dll", "NtCreateProcess");
    Real_NtCreateThread = (pNtCreateThread)DetourFindFunction("ntdll.dll", "NtCreateThread");
    Real_NtCreateThreadEx = (pNtCreateThreadEx)DetourFindFunction("ntdll.dll", "NtCreateThreadEx");
    Real_NtOpenProcess = (pNtOpenProcess)DetourFindFunction("ntdll.dll", "NtOpenProcess");
    Real_NtLoadDriver = (pNtLoadDriver)DetourFindFunction("ntdll.dll", "NtLoadDriver");
    Real_NtCreateNamedPipeFile = (pNtCreateNamedPipeFile)DetourFindFunction("ntdll.dll", "NtCreateNamedPipeFile");
    Real_NtCreateSection = (pNtCreateSection)DetourFindFunction("ntdll.dll", "NtCreateSection");
    Real_NtCreateProcessEx = (pNtCreateProcessEx)DetourFindFunction("ntdll.dll", "NtCreateProcessEx");
    Real_NtCreateEvent = (pNtCreateEvent)DetourFindFunction("ntdll.dll", "NtCreateEvent");
    Real_NtCreateTimer = (pNtCreateTimer)DetourFindFunction("ntdll.dll", "NtCreateTimer");
    Real_NtCreateTimer2 = (pNtCreateTimer2)DetourFindFunction("ntdll.dll", "NtCreateTimer2");
    Real_NtReadVirtualMemory = (pNtReadVirtualMemory)DetourFindFunction("ntdll.dll", "NtReadVirtualMemory");
    Real_NtOpenThread = (pNtOpenThread)DetourFindFunction("ntdll.dll", "NtOpenThread");
    Real_NtWriteVirtualMemory = (t_NtWriteVirtualMemory)DetourFindFunction("ntdll.dll", "NtWriteVirtualMemory");
    Real_NtMapViewOfSection = (t_NtMapViewOfSection)DetourFindFunction("ntdll.dll", "NtMapViewOfSection");
    Real_NtAllocateVirtualMemory = (t_NtAllocateVirtualMemory)DetourFindFunction("ntdll.dll", "NtAllocateVirtualMemory");
    Real_NtProtectVirtualMemory = (t_NtProtectVirtualMemory)DetourFindFunction("ntdll.dll", "NtProtectVirtualMemory");
    Real_NtFreeVirtualMemory = (t_NtFreeVirtualMemory)DetourFindFunction("ntdll.dll", "NtFreeVirtualMemory");
    Real_NtResumeThread = (pNtResumeThread)DetourFindFunction("ntdll.dll", "NtResumeThread");

    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // All the hooks
    //DetourAttach(&(PVOID&)Real_NtSetContextThread, Catch_NtSetContextThread); // broken
    //DetourAttach(&(PVOID&)Real_LdrLoadDll, Catch_LdrLoadDll); // broken
    DetourAttach(&(PVOID&)Real_LdrGetProcedureAddress, Catch_LdrGetProcedureAddress);
    DetourAttach(&(PVOID&)Real_NtQueueApcThread, Catch_NtQueueApcThread);
    DetourAttach(&(PVOID&)Real_NtQueueApcThreadEx, Catch_NtQueueApcThreadEx);
    DetourAttach(&(PVOID&)Real_NtCreateProcess, Catch_NtCreateProcess);
    DetourAttach(&(PVOID&)Real_NtCreateThread, Catch_NtCreateThread);
    DetourAttach(&(PVOID&)Real_NtCreateThreadEx, Catch_NtCreateThreadEx);
    DetourAttach(&(PVOID&)Real_NtResumeThread, Catch_NtResumeThread);
    DetourAttach(&(PVOID&)Real_NtOpenProcess, Catch_NtOpenProcess);
    DetourAttach(&(PVOID&)Real_NtLoadDriver, Catch_NtLoadDriver);
    DetourAttach(&(PVOID&)Real_NtCreateNamedPipeFile, Catch_NtCreateNamedPipeFile);
    DetourAttach(&(PVOID&)Real_NtCreateSection, Catch_NtCreateSection);
    DetourAttach(&(PVOID&)Real_NtCreateProcessEx, Catch_NtCreateProcessEx);
    DetourAttach(&(PVOID&)Real_NtCreateEvent, Catch_NtCreateEvent);
    DetourAttach(&(PVOID&)Real_NtCreateTimer, Catch_NtCreateTimer);
    DetourAttach(&(PVOID&)Real_NtCreateTimer2, Catch_NtCreateTimer2);
    DetourAttach(&(PVOID&)Real_NtReadVirtualMemory, Catch_NtReadVirtualMemory);
    DetourAttach(&(PVOID&)Real_NtOpenThread, Catch_NtOpenThread);
    DetourAttach(&(PVOID&)Real_NtWriteVirtualMemory, Catch_NtWriteVirtualMemory);
    DetourAttach(&(PVOID&)Real_NtMapViewOfSection, Catch_NtMapViewOfSection);
    DetourAttach(&(PVOID&)Real_NtAllocateVirtualMemory, Catch_NtAllocateVirtualMemory);
    DetourAttach(&(PVOID&)Real_NtProtectVirtualMemory, Catch_NtProtectVirtualMemory);
    DetourAttach(&(PVOID&)Real_NtFreeVirtualMemory, Catch_NtFreeVirtualMemory);

    error = DetourTransactionCommit();
    if (error == NO_ERROR) {
        LOG_A(LOG_INFO, "simple" DETOURS_STRINGIFY(DETOURS_BITS) ".dll: Detoured SleepEx().\n");
    }
    else {
        LOG_A(LOG_ERROR, "simple" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:Error detouring SleepEx(): %ld\n", error);
    }
    SendDllPipe(stop_str);
    HooksInitialized = TRUE;

    return 0;
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }
    if (dwReason == DLL_PROCESS_ATTACH) {
        InitHooksThread(NULL);
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        /* DetourTransactionBegin();
         DetourUpdateThread(GetCurrentThread());
         DetourDetach(&(PVOID&)TrueSleepEx, TimedSleepEx);
         error = DetourTransactionCommit();

         printf("simple" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
             " Removed SleepEx() (result=%ld), slept %ld ticks.\n", error, dwSlept);
         fflush(stdout);
         */
    }
    return TRUE;
}