#include <stdio.h>
#include <Windows.h>
//#include "ppl_runner.h"

#include "loguru.hpp"
#include "../Shared/common.h"



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
            LOG_F(INFO, "[PPL_RUNNER] install_service: CreateService Error: Service '%s' Already Exists", SERVICE_NAME);
            LOG_F(INFO, "[PPL_RUNNER] install_service: Run 'net start %s' to start the service", SERVICE_NAME);
        }
        else {
            LOG_F(ERROR, "[PPL_RUNNER] install_service: CreateService Error: %d", retval);
        }
        return retval;
    }

    // Mark service as protected
    info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
    if (ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &info) == FALSE) {
        retval = GetLastError();
        LOG_F(ERROR, "[PPL_RUNNER] install_service: ChangeServiceConfig2 Error: %d", retval);
        return retval;
    }
    LOG_F(INFO, "[PPL_RUNNER] install_service: install_service: Created Service: %s", serviceCMD);
    LOG_F(INFO, "[PPL_RUNNER] install_service: Run 'net start %s' to start the service", SERVICE_NAME);
    return retval;
}


DWORD remove_ppl_service() {
    DWORD retval = 0;
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    LOG_F(INFO, "[PPL_RUNNER] remove_service: Stopping and Deleting Service %s...", SERVICE_NAME);

    // Get Handle to Service Manager and Service
    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
        retval = GetLastError();
        LOG_F(ERROR, "[PPL_RUNNER] remove_service: OpenSCManager Error: %d", retval);
        return retval;

    }
    hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (hService == NULL) {
        retval = GetLastError();
        LOG_F(ERROR, "[PPL_RUNNER] remove_service: OpenService Error: %d", retval);
        return retval;
    }

    // Get status of service
    if (!QueryServiceStatusEx(
        hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        retval = GetLastError();
        LOG_F(ERROR, "[PPL_RUNNER] remove_service: QueryServiceStatusEx1 Error: %d", retval);
        return retval;
    }

    if (ssp.dwCurrentState != SERVICE_STOPPED) {
        // Send a stop code to the service.
        if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp)) {
            retval = GetLastError();
            LOG_F(ERROR, "[PPL_RUNNER] remove_service: ControlService(Stop) Error: %d", retval);
            return retval;
        }
        if (ssp.dwCurrentState != SERVICE_STOPPED) {
            // Wait for service to die
            Sleep(3000);
            if (!QueryServiceStatusEx(
                hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
                retval = GetLastError();
                LOG_F(ERROR, "[PPL_RUNNER] remove_service: QueryServiceStatusEx2 Error: %d", retval);
                return retval;
            }
            if (ssp.dwCurrentState != SERVICE_STOPPED) {
                retval = ssp.dwCurrentState;
                LOG_F(ERROR, "[PPL_RUNNER] remove_service: Waited but service still not stopped: %d", retval);
                return retval;
            }
        }
    }

    // Service stopped, now remove it
    if (!DeleteService(hService)) {
        retval = GetLastError();
        LOG_F(ERROR, "[PPL_RUNNER] remove_service: DeleteService Error: %d", retval);
        return retval;
    }

    LOG_F(INFO, "[PPL_RUNNER] remove_service: Deleted Service %s", SERVICE_NAME);

    return retval;
}


