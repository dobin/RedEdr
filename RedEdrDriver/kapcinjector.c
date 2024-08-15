
#include <ntifs.h>

// from https://github.com/0xOvid/RootkitDiaries/


// set dispach drivers

/*
PsSetLoadImageNotifyRoutine

check process
allocate memory for the KeInitializeApc and KeInsertQueueApc

KAPC *Alloc=(KAPC*)ExAllocatePool(NonPagedPool,sizeof(KAPC)


For another post, create and delete the same device
ObMakeTemporaryObject
*/


/*
Defining basic data structures
*/
typedef PVOID(*fnLoadLibraryExA)(
	LPCSTR lpLibFileName,
	HANDLE hFile,
	ULONG dwFlag
	);

typedef struct _INJECTION_DATA // _SIRIFEF_INJECTION_DATA in article
{
	BOOLEAN Executing;
	PEPROCESS Process;
	PETHREAD Ethread;
	KEVENT Event;
	WORK_QUEUE_ITEM WorkItem;
	ULONG ProcessId;
} INJECTION_DATA, * P_INJECTION_DATA;

typedef struct GET_ADDRESS
{
	PVOID Kernel32dll;
	fnLoadLibraryExA pvLoadLibraryExA;
}GET_ADDRESS, * PGET_ADDRESS;

// Define undocumented structures
typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
}KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID KKERNEL_ROUTINE(
	PRKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
);

typedef KKERNEL_ROUTINE(NTAPI* PKKERNEL_ROUTINE);

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(
	PRKAPC Apc
	);

void KeInitializeApc(
	PRKAPC Apc,
	PRKTHREAD Thread,
	KAPC_ENVIRONMENT Environment,
	PKKERNEL_ROUTINE KernelRoutine,
	PKRUNDOWN_ROUTINE RundownRoutine,
	PKNORMAL_ROUTINE NormalRoutine,
	KPROCESSOR_MODE ProcessorMode,
	PVOID NormalContext
);

BOOLEAN KeInsertQueueApc(
	PRKAPC Apc,
	PVOID SystemArgument1,
	PVOID SystemArgument2,
	KPRIORITY Increment
);

PVOID pLoadLibraryExA = { 0 };

VOID NTAPI APCKernelRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* SysArg1, PVOID* SysArg2, PVOID* Context)
{
	UNREFERENCED_PARAMETER(Apc);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(SysArg1);
	UNREFERENCED_PARAMETER(SysArg2);
	UNREFERENCED_PARAMETER(Context);
	ExFreePool(Apc);
	return;
}

NTSTATUS DllInject(HANDLE ProcessId, PEPROCESS PeProcess, PETHREAD PeThread, BOOLEAN Alert)
{
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(PeProcess);
	UNREFERENCED_PARAMETER(PeThread);
	UNREFERENCED_PARAMETER(Alert);

	NTSTATUS status;


	// 3) open the target process using the id that we gather before	
	HANDLE hProcess; // The ZwOpenProcess routine writes the process handle to the 
	// variable that this parameter points to.
	OBJECT_ATTRIBUTES objectAttributes = { sizeof(OBJECT_ATTRIBUTES) };
	CLIENT_ID clientId;

	InitializeObjectAttributes(&objectAttributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);
	clientId.UniqueProcess = PsGetProcessId(PeProcess); ProcessId;
	clientId.UniqueThread = (HANDLE)0;
	status = ZwOpenProcess(&hProcess,
		PROCESS_ALL_ACCESS,
		&objectAttributes,
		&clientId);
	// Check for successfull allocation
	if (!(NT_SUCCESS(status)))
	{
		KdPrint(("[ERROR] ZwOpenProcess Failed\n"));
		return STATUS_NO_MEMORY;
	}

	CHAR DllFormatPath[] = "C:\\RedEdr\\RedEdrDll.dll";
	// 2) get the size in bytes of the string
	SIZE_T Size = strlen(DllFormatPath) + 1;
	PVOID pvMemory = NULL;
	KdPrint(("[+] ZwOpenProcess!!!\n"));

	// 4) Allocate memory on the target process calling ZwAllocateVirtualMemory 
	// with the bytes of the string as the size for the allocation.
	status = ZwAllocateVirtualMemory(hProcess, &pvMemory, 0, &Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// check for successfull allocation
	if (!(NT_SUCCESS(status)))
	{
		KdPrint(("[ERROR] ZwAllocateVirtualMemory Failed\n"));
		ZwClose(hProcess);
		return STATUS_NO_MEMORY;
	}

	KAPC_STATE KasState;
	PKAPC Apc;
	// 5) KeStackAttachProcess which attaches the current thread to the target process address space
	KeStackAttachProcess(PeProcess, &KasState);
	// 6) Copy the string to the previously allocated memory
	strcpy(pvMemory, DllFormatPath);
	// 7) KeUnstackDetachProcess which detaches the current thread and restores the old attach state.
	KeUnstackDetachProcess(&KasState);
	// 8) Allocate memory again for an KAPC variable
	//Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
	Apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'Tag1');
	if (Apc)
	{
		// 9) Initialize the APC inserting the address of the stub LoadLibraryExA and the allocated 
		// memory which contains the path of the dll
		KeInitializeApc(Apc,
			PeThread,
			0,
			(PKKERNEL_ROUTINE)APCKernelRoutine,
			0,
			(PKNORMAL_ROUTINE)pLoadLibraryExA,
			UserMode,
			pvMemory);
		// 10) Insert the APC
		KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);
		KdPrint(("[+] SUCCESS!!!\n"));
		return STATUS_SUCCESS;
	}
	return STATUS_NO_MEMORY;
}

VOID WorkerRoutine(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	DllInject(&((P_INJECTION_DATA)Context)->ProcessId, ((P_INJECTION_DATA)Context)->Process, ((P_INJECTION_DATA)Context)->Ethread, FALSE);
	KeSetEvent(&((P_INJECTION_DATA)Context)->Event, (KPRIORITY)0, FALSE);
	return;
}

// ExInitializeWorkItem and ExQueueWorkItem are deprecated. I dont care.
#pragma warning(push)
#pragma warning(disable: 4996)
VOID NTAPI APCInjectorRoutine(PKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* SystemArgument1, PVOID* SystemArgument2, PVOID* Context)
{
	UNREFERENCED_PARAMETER(Apc);
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	UNREFERENCED_PARAMETER(Context);

	KdPrint(("[+] APCInjectorRoutine\n"));
	
	// The APCInjectorRoutine Initializes the SIRIFEF_INJECTION_DATA structure and frees the apc value everytime its called.
	INJECTION_DATA Sf;

	RtlSecureZeroMemory(&Sf, sizeof(INJECTION_DATA));
	ExFreePool(Apc);
	// 1) Pass the current thread memory to the structure
	Sf.Ethread = KeGetCurrentThread();
	// 2) Pass the the current process to the structure
	Sf.Process = IoGetCurrentProcess();
	// 3) Pass the current process id to the structure
	//Sf.ProcessId = PsGetCurrentProcessId();
	// 4) Initialize the notification event
	KeInitializeEvent(&Sf.Event, NotificationEvent, FALSE);

	// 5) Initialize the WorkItem, queue the work item with type DelayedWorkItem
	ExInitializeWorkItem(&Sf.WorkItem, (PWORKER_THREAD_ROUTINE)WorkerRoutine, &Sf);  // deprecated
	// 6) Wait for the event object
	ExQueueWorkItem(&Sf.WorkItem, DelayedWorkQueue);  // deprecated
	KeWaitForSingleObject(&Sf.Event, Executive, KernelMode, TRUE, 0);
	
	/*
	// Alternative to the deprecated functions, untested
	// 4) Allocate and initialize the WorkItem using IoAllocateWorkItem
	Sf.WorkItem = IoAllocateWorkItem(Sf.Process);
	if (Sf.WorkItem == NULL) {
		// Handle allocation failure
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	// 5) Queue the work item with type DelayedWorkItem
	IoQueueWorkItem(Sf.WorkItem, (PIO_WORKITEM_ROUTINE)WorkerRoutine, DelayedWorkQueue, &Sf);
	// 6) Wait for the event object
	KeWaitForSingleObject(&Sf.Event, Executive, KernelMode, TRUE, 0);
	// 7) Free the work item after it has been processed
	IoFreeWorkItem(Sf.WorkItem);
	*/

	return;
}

#include <ntimage.h>
PVOID CustomGetProcAddress(PVOID pModuleBase, UNICODE_STRING functionName) {
	UNREFERENCED_PARAMETER(functionName);
	// Check PE header for magic bytes
	PIMAGE_DOS_HEADER ImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return NULL;
	}
	// Check PE header for signature
	PIMAGE_NT_HEADERS ImageNtHeaders = ((PIMAGE_NT_HEADERS)(RtlOffsetToPointer(pModuleBase, ImageDosHeader->e_lfanew)));
	if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return NULL;
	}
	// Check Optional Headers
	if (!(ImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress &&
		0 < ImageNtHeaders->OptionalHeader.NumberOfRvaAndSizes)) {
		return NULL;
	}
	// Get address of Export directory
	PIMAGE_EXPORT_DIRECTORY ImageExport = (((PIMAGE_EXPORT_DIRECTORY)(PUCHAR)RtlOffsetToPointer(pModuleBase, ImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress)));
	// Check for export directory
	if (!(ImageExport))
	{
		return NULL;
	}
	PULONG AddressOfNames = ((PULONG)RtlOffsetToPointer(pModuleBase, ImageExport->AddressOfNames));
	for (ULONG n = 0; n < ImageExport->NumberOfNames; ++n)
	{
		LPSTR FunctionName = ((LPSTR)RtlOffsetToPointer(pModuleBase, AddressOfNames[n]));
		if (strcmp("LoadLibraryExA", FunctionName) == 0) {
			PULONG AddressOfFunctions = ((PULONG)RtlOffsetToPointer(pModuleBase, ImageExport->AddressOfFunctions));
			PUSHORT AddressOfOrdinals = ((PUSHORT)RtlOffsetToPointer(pModuleBase, ImageExport->AddressOfNameOrdinals));

			PVOID pFnLoadLibraryExA = ((PVOID)RtlOffsetToPointer(pModuleBase, AddressOfFunctions[AddressOfOrdinals[n]]));

			KdPrint(("[+] FOUND! functionName %s @ %p\n", FunctionName, pFnLoadLibraryExA));

			return pFnLoadLibraryExA;
		}
	}
	return NULL;
}

int kapc_inject(IN PUNICODE_STRING ImageName, IN HANDLE ProcessId, IN PIMAGE_INFO pImageInfo) {
	UNREFERENCED_PARAMETER(ImageName);
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(pImageInfo);
	// Source: https://github.com/alexvogt91/Kernel-dll-injector/blob/master/Sirifef/Sirifef/Sf.c

	// 1) First check that the ImageName which is a pointer to an UNICODE_STRING structure is not 0
	if (ImageName == NULL) {
		return 0;
	}
	WCHAR kernel32mask[] = L"*\\KERNEL32.DLL";
	UNICODE_STRING kernel32unicodeString;
	// initialize unicode string
	RtlInitUnicodeString(&kernel32unicodeString, kernel32mask);
	// 2) Check that the string kernel32.dll exists, since we will be injecting our dll code only when system loads kernel32.dll module.
	if (!(FsRtlIsNameInExpression(&kernel32unicodeString, ImageName, TRUE, NULL))) {
		return 0;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] kernel32.dll match\n");
	/*
	* How it was done in the original:
	3) Hash variable its actually a global variable(in real production malware this would be change) defined like this GET_ADDRESS Hash.
	4) If the kernel32dll value is zero, that means it has not loaded yet, so we enter the conditional,
		pass the memory from the loaded module by the notification(kernel32.dll) and load the
		LoadLibraryExA function using the ResolveDynamicImport which can be found in the ZeroBank rootkit series.

	Flow in source:
	check if the hash value is empty
	if so call resolveDynamicImport using the base address of the dll
	resolveDynamicImport calls a custom implementaiton of get proc address
	SIRIFEF_LOADLIBRARYEXA_ADDRESS is defined as: #define SIRIFEF_LOADLIBRARYEXA_ADDRESS 1268416216
	this is used in the custom get proc address function as so:
	- parse PE header and check magic byre for MZ
	- check signature
	- Check exported functions
	- Resolve address of names
	- walk names and look for the one with the matching hash
	- when hashes match return pointer to the function
	*/
	pLoadLibraryExA = CustomGetProcAddress((PVOID)pImageInfo->ImageBase, kernel32unicodeString);

	// 5) Next step is to allocate memory for an KAPC variable
	PKAPC Apc;
	//Apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
	Apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), 'Tag1');
	if (!Apc)
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[ ] apc error\n");
		return 0;
	}
	//KdPrint(("[+] APC allocated\n"));

	// 6) Initialize the Apc with KeInitializeApc using the current thread and introducing the function APCInjectorRoutine, the processor mode is kernelmode.
	KeInitializeApc(Apc, KeGetCurrentThread(), OriginalApcEnvironment, (PKKERNEL_ROUTINE)APCInjectorRoutine, 0, 0, KernelMode, 0);
	// 7) Insert the Apc with KeInsertQueueApc
	KeInsertQueueApc(Apc, 0, 0, IO_NO_INCREMENT);

	return 1;
}
