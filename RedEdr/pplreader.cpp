#include <stdio.h>
#include <Windows.h>
//#include "ppl_runner.h"

#include "loguru.hpp"
#include "../Shared/common.h"


BOOL pplreader_enable(BOOL e) {
    DWORD bytesWritten;
    wchar_t buffer[DATA_BUFFER_SIZE] = { 0 };
    HANDLE hPipe;
    int n = 0;
    DWORD len;

    hPipe = CreateFile(
        PPL_SERVICE_PIPE_NAME,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "Error creating named pipe: %ld\n", GetLastError());
        return 1;
    }

    if (e) {
        wcscpy_s(buffer, DATA_BUFFER_SIZE, L"start");
        len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
        if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
            LOG_F(ERROR, "Error writing to named pipe: %ld\n", GetLastError());
            CloseHandle(hPipe);
            return FALSE;
        }
        LOG_F(INFO, "ppl reader: Enabled");
    }
    else {
        wcscpy_s(buffer, DATA_BUFFER_SIZE, L"stop");
        len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
        if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
            LOG_F(ERROR, "Error writing to named pipe: %ld\n", GetLastError());
            CloseHandle(hPipe);
            return FALSE;
        }
        LOG_F(INFO, "ppl reader: Disabled");
    }

    CloseHandle(hPipe);
    return TRUE;
}


DWORD install_elam_cert()
{
    DWORD retval = 0;
    HANDLE fileHandle = NULL;
    WCHAR driverName[] = DRIVER_NAME;

    LOG_F(INFO, "[PPL_RUNNER] install_elam_cert: Opening driver file: %s", driverName);
    fileHandle = CreateFile(driverName,
        FILE_READ_DATA,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (fileHandle == INVALID_HANDLE_VALUE) {
        retval = GetLastError();
        LOG_F(ERROR, "[PPL_RUNNER] install_elam_cert: CreateFile Error: %d", retval);
        return retval;
    }

    if (InstallELAMCertificateInfo(fileHandle) == FALSE) {
        retval = GetLastError();
        LOG_F(ERROR, "[PPL_RUNNER] install_elam_cert: install_elam_certificateInfo Error: %d", retval);
        return retval;
    }
    LOG_F(INFO, "[PPL_RUNNER] install_elam_cert: Installed ELAM driver cert");

    return retval;
}


DWORD install_ppl_service()
{
    DWORD retval = 0;
    SERVICE_LAUNCH_PROTECTED_INFO info;
    SC_HANDLE hService;
    SC_HANDLE hSCManager;
    BOOL bSuccess = FALSE;

    DWORD SCManagerAccess = SC_MANAGER_ALL_ACCESS;
    hSCManager = OpenSCManager(NULL, NULL, SCManagerAccess);
    if (hSCManager == NULL) {
        retval = GetLastError();
        LOG_F(ERROR, "[PPL_RUNNER] install_service: OpenSCManager Error: %d", retval);
        return retval;

    }

    WCHAR serviceCMD[MAX_BUF_SIZE] = L"c:\\RedEdr\\RedEdrPplService.exe";

    // Add PPL option
    hService = CreateService(
        hSCManager,
        SERVICE_NAME,
        SERVICE_NAME,
        SCManagerAccess,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,
        SERVICE_ERROR_NORMAL,
        serviceCMD,
        NULL,
        NULL,
        NULL,
        NULL, /* ServiceAccount */
        NULL
    );
    if (hService == NULL) {
        retval = GetLastError();
        if (retval == ERROR_SERVICE_EXISTS) {
            LOG_F(INFO, "[PPL_RUNNER] install_service: CreateService: Service '%s' Already Exists", SERVICE_NAME);
            //LOG_F(INFO, "[PPL_RUNNER] install_service: Run 'net start %s' to start the service", SERVICE_NAME);
        }
        else {
            LOG_F(ERROR, "[PPL_RUNNER] install_service: CreateService Error: %d", retval);
            return retval;
        }
    }
    else {
        // Mark service as protected
        info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
        if (ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &info) == FALSE) {
            retval = GetLastError();
            LOG_F(ERROR, "[PPL_RUNNER] install_service: ChangeServiceConfig2 Error: %d", retval);
            return retval;
        }
    }

    //LOG_F(INFO, "[PPL_RUNNER] install_service: install_service: Created Service: %s", serviceCMD);
    //LOG_F(INFO, "[PPL_RUNNER] install_service: Run 'net start %s' to start the service", SERVICE_NAME);

    // Start service
    hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (hService == NULL) {
        retval = GetLastError();
        LOG_F(ERROR, "OpenService failed, error: %d\n", retval);
        CloseServiceHandle(hSCManager);
        return retval;
    }
    bSuccess = StartService(hService, 0, NULL);
    if (!bSuccess) {
        retval = GetLastError();
        if (retval == ERROR_SERVICE_ALREADY_RUNNING) {
            LOG_F(WARNING, "Service is already running.\n");
        }
        else {
            LOG_F(ERROR, "StartService failed, error: %d\n", retval);
        }
    }
    else {
        LOG_F(INFO, "Service started successfully.\n");
    }

    // Close handles
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return retval;
}


DWORD remove_ppl_service() {
    DWORD retval = 0;
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    LOG_F(INFO, "[REDEDR_PPL] remove_service() fuckmesideways");
    //LOG_F(INFO, "[REDEDR_PPL] remove_service: Stopping and Deleting Service %s...", SERVICE_NAME);

    // Get Handle to Service Manager and Service
    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
        retval = GetLastError();
        LOG_F(ERROR, "[REDEDR_PPL] remove_service: OpenSCManager Error: %d", retval);
        return retval;

    }
    hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (hService == NULL) {
        retval = GetLastError();
        LOG_F(ERROR, "[REDEDR_PPL] remove_service: OpenService Error: %d", retval);
        return retval;
    }

    // Get status of service
    if (!QueryServiceStatusEx(
        hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        retval = GetLastError();
        LOG_F(ERROR, "[REDEDR_PPL] remove_service: QueryServiceStatusEx1 Error: %d", retval);
        return retval;
    }

    if (ssp.dwCurrentState != SERVICE_STOPPED) {
        // Send a stop code to the service.
        if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp)) {
            retval = GetLastError();
            LOG_F(ERROR, "[REDEDR_PPL] remove_service: ControlService(Stop) Error: %d", retval);
            return retval;
        }
        if (ssp.dwCurrentState != SERVICE_STOPPED) {
            // Wait for service to die
            Sleep(3000);
            if (!QueryServiceStatusEx(
                hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
                retval = GetLastError();
                LOG_F(ERROR, "[REDEDR_PPL] remove_service: QueryServiceStatusEx2 Error: %d", retval);
                return retval;
            }
            if (ssp.dwCurrentState != SERVICE_STOPPED) {
                retval = ssp.dwCurrentState;
                LOG_F(ERROR, "[REDEDR_PPL] remove_service: Waited but service still not stopped: %d", retval);
                return retval;
            }
        }
    }

    // Service stopped, now remove it
    if (!DeleteService(hService)) {
        retval = GetLastError();
        LOG_F(ERROR, "[REDEDR_PPL] remove_service: DeleteService Error: %d", retval);
        return retval;
    }

    LOG_F(INFO, "[REDEDR_PPL] remove_service: Deleted Service %s", SERVICE_NAME);

    return retval;
}
