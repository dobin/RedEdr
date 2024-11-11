#include <stdio.h>
#include <windows.h>
#include <cwchar>  // For wcstol
#include <cstdlib> // For exit()
#include <string.h>
#include <stdio.h>
#include "../Shared/common.h"
#include "logging.h"
#include "config.h"
#include "processinfo.h"
#include "dllinjector.h"

#include "serviceutils.h"


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


BOOL IsServiceRunning(LPCWSTR driverName) {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS_PROCESS status;
    DWORD bytesNeeded;
    //LPCWSTR driverName = g_config.driverName;
    BOOL ret = FALSE;

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        LOG_A(LOG_ERROR, "Kernel: OpenSCManager failed. Error: %lu", GetLastError());
        return FALSE;
    }

    hService = OpenService(hSCManager, driverName, SERVICE_QUERY_STATUS);
    if (!hService) {
        //LOG_A(LOG_ERROR, "OpenService failed. Error: %lu", GetLastError());
        ret = FALSE;
        goto cleanup;
    }

    if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
        //LOG_A(LOG_ERROR, "KernelDriver: Servicestatus:");
        //LOG_A(LOG_ERROR, "  PID: %lu", status.dwProcessId);
        //LOG_A(LOG_ERROR, "  State: %lu", status.dwCurrentState);
        ret = TRUE;
    }
    else {
        LOG_A(LOG_ERROR, "Kernel: QueryServiceStatusEx failed. Error: %lu", GetLastError());
        ret = FALSE;
    }

cleanup:
    if (hService) CloseServiceHandle(hService);
    if (hSCManager) CloseServiceHandle(hSCManager);

    return ret;
}
