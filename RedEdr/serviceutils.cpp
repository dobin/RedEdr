#include <stdio.h>
#include <windows.h>
#include <cwchar>  // For wcstol
#include <cstdlib> // For exit()
#include <string.h>
#include <stdio.h>
#include <sddl.h> // For ConvertSidToStringSid


#include "../Shared/common.h"
#include "logging.h"
#include "config.h"
#include "process_query.h"
#include "dllinjector.h"

#include "serviceutils.h"


BOOL PermissionMakeMeDebug() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("Permissions: OpenProcessToken failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Debug too
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("Permissions: LookupPrivilegeValue failed. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // Privileged!

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("Permissions: Could not apply specified privilege: PRIVILEGED\n");
        CloseHandle(hToken);
        return FALSE;
    }

    LOG_A(LOG_INFO, "Permissions: Enabled PRIVILEGED & DEBUG");
    CloseHandle(hToken);
    return TRUE;
}


BOOL IsRunningAsSystem() {
    HANDLE hToken = NULL;

    // Open the current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::cerr << "Failed to open process token. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Get the size of the token information
    DWORD dwBufferSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get token information size. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    // Allocate buffer for the token information
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwBufferSize);
    if (!pTokenUser) {
        std::cerr << "Memory allocation failed." << std::endl;
        CloseHandle(hToken);
        return false;
    }

    // Retrieve the token information
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
        std::cerr << "Failed to get token information. Error: " << GetLastError() << std::endl;
        free(pTokenUser);
        CloseHandle(hToken);
        return false;
    }

    // Convert the SID to a string
    LPTSTR sidString = NULL;
    if (!ConvertSidToStringSid(pTokenUser->User.Sid, &sidString)) {
        std::cerr << "Failed to convert SID to string. Error: " << GetLastError() << std::endl;
        free(pTokenUser);
        CloseHandle(hToken);
        return false;
    }

    // Check if the SID corresponds to SYSTEM
    bool isSystem = (_tcscmp(sidString, _T("S-1-5-18")) == 0); // SYSTEM SID: S-1-5-18
    /*
    if (isSystem) {
        std::cout << "The process is running as SYSTEM." << std::endl;
    }
    else {
        std::cout << "The process is NOT running as SYSTEM. SID: " << sidString << std::endl;
    }
    */

    // Cleanup
    LocalFree(sidString);
    free(pTokenUser);
    CloseHandle(hToken);

    return isSystem;
}


BOOL DoesServiceExist(LPCWSTR serviceName) {
    // Open the Service Control Manager
    SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scmHandle) {
        std::wcerr << L"Failed to open Service Control Manager. Error: " << GetLastError() << std::endl;
        return FALSE;
    }

    // Try to open the service
    SC_HANDLE serviceHandle = OpenService(scmHandle, serviceName, SERVICE_QUERY_STATUS);
    if (serviceHandle) {
        // The service exists, close handles and return true
        CloseServiceHandle(serviceHandle);
        CloseServiceHandle(scmHandle);
        return TRUE;
    }

    // Check if the error is due to the service not existing
    //DWORD error = GetLastError();
    //CloseServiceHandle(scmHandle);
    //return error != ERROR_SERVICE_DOES_NOT_EXIST ? true : false;
    return FALSE;
}


// https://gist.github.com/the-nose-knows/607dba810fa7fc1db761e4f0ad1fe464
BOOL IsServiceRunning(LPCWSTR driverName) {
	SC_HANDLE scm = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
	if (scm == NULL)
		return false;
	LPCWSTR   lpServiceName = driverName;

	SC_HANDLE hService = OpenService(scm, lpServiceName, GENERIC_READ);
	if (hService == NULL)
	{
		CloseServiceHandle(scm);
		return false;
	}

	SERVICE_STATUS status;
	LPSERVICE_STATUS pstatus = &status;
	if (QueryServiceStatus(hService, pstatus) == 0)
	{
		CloseServiceHandle(hService);
		CloseServiceHandle(scm);
		return false;
	}

	CloseServiceHandle(hService);
	CloseServiceHandle(scm);
	return (status.dwCurrentState == SERVICE_RUNNING) ? (true) : (false);
}
