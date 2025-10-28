#include <windows.h>
#include <iostream>

#include "serviceutils.h"
#include "logging.h"

BOOL DoesServiceExist(LPCWSTR serviceName) {
    // Open the Service Control Manager
    SC_HANDLE scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scmHandle) {
        LOG_W(LOG_ERROR, L"Failed to open Service Control Manager. Error: %d", GetLastError());
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
