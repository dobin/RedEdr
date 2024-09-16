#include <stdio.h>
#include <Windows.h>
//#include "ppl_runner.h"

#include "loguru.hpp"
#include "../Shared/common.h"
#include "serviceutils.h"


BOOL EnablePplService(BOOL e, wchar_t* target_name) {
    DWORD bytesWritten;
    wchar_t buffer[DATA_BUFFER_SIZE] = { 0 };
    HANDLE hPipe;
    int n = 0;
    DWORD len;

    if (!IsServiceRunning(SERVICE_NAME)) {
        LOG_F(ERROR, "Error: service %ls not found", SERVICE_NAME);
        LOG_F(ERROR, "ETW-TI: Is RedEdrPplService loaded?");
        LOG_F(ERROR, "ETW-TI:   (requires self-signed kernel and elam driver for ppl)");
        return FALSE;
    }

    hPipe = CreateFile(
        PPL_SERVICE_PIPE_NAME,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        LOG_F(ERROR, "ETW-TI: Error creating named pipe: error code %ld", GetLastError());
        LOG_F(ERROR, "ETW-TI: Is RedEdrPplService running?");
        LOG_F(ERROR, "ETW-TI:   (requires self-signed kernel and elam driver for ppl)");
        return 1;
    }

    // Send enable/disable via pipe to PPL aervice
    if (e) {
        if (target_name == NULL) {
            LOG_F(ERROR, "ETW-TI: Enable, but no target name given. Abort.");
            return FALSE;
        }
        swprintf_s(buffer, sizeof(buffer) / sizeof(buffer[0]), L"start:%s", target_name);
        //wcscpy_s(buffer, DATA_BUFFER_SIZE, L"start");
        len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
        if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
            LOG_F(ERROR, "ETW-TI: Error writing to named pipe: %ld", GetLastError());
            CloseHandle(hPipe);
            return FALSE;
        }
        LOG_F(INFO, "ETW-TI: ppl reader: Enabled");
    }
    else {
        wcscpy_s(buffer, DATA_BUFFER_SIZE, L"stop");
        len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
        if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
            LOG_F(ERROR, "ETW-TI: Error writing to named pipe: %ld", GetLastError());
            CloseHandle(hPipe);
            return FALSE;
        }
        LOG_F(INFO, "ETW-TI: ppl reader: Disabled");
    }

    CloseHandle(hPipe);
    return TRUE;
}


BOOL ShutdownPplService() {
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
        LOG_F(ERROR, "ETW-TI: Error creating named pipe: %ld", GetLastError());
        return 1;
    }

    wcscpy_s(buffer, DATA_BUFFER_SIZE, L"shutdown");
    len = (wcslen(buffer) * 2) + 2; // w is 2 bytes, and include trailing \0 as delimitier
    if (!WriteFile(hPipe, buffer, len, &bytesWritten, NULL)) {
        LOG_F(ERROR, "ETW-TI: Error writing to named pipe: %ld", GetLastError());
        CloseHandle(hPipe);
        return FALSE;
    }
    LOG_F(INFO, "ETW-TI: ppl reader: Disabled");

    CloseHandle(hPipe);
    return TRUE;
}


DWORD InstallElamCertPpl()
{
    DWORD retval = 0;
    HANDLE fileHandle = NULL;
    WCHAR driverName[] = DRIVER_NAME;

    LOG_F(INFO, "ETW-TI: install_elam_cert: Opening driver file: %ls", driverName);
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
        LOG_F(ERROR, "ETW-TI: install_elam_cert: CreateFile Error: %d", retval);
        return retval;
    }

    if (InstallELAMCertificateInfo(fileHandle) == FALSE) {
        retval = GetLastError();
        LOG_F(ERROR, "ETW-TI: install_elam_cert: install_elam_certificateInfo Error: %d", retval);
        return retval;
    }
    LOG_F(INFO, "ETW-TI: install_elam_cert: Installed ELAM driver cert");

    return retval;
}


DWORD InstallPplService()
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
        LOG_F(ERROR, "ETW-TI: install_service: OpenSCManager Error: %d", retval);
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
            LOG_F(INFO, "ETW-TI: install_service: CreateService: Service '%ls' Already Exists", SERVICE_NAME);
            //LOG_F(INFO, "[PPL_RUNNER] install_service: Run 'net start %s' to start the service", SERVICE_NAME);
        }
        else {
            LOG_F(ERROR, "ETW-TI: install_service: CreateService Error: %d", retval);
            return retval;
        }
    }
    else {
        // Mark service as protected
        info.dwLaunchProtected = SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT;
        if (ChangeServiceConfig2(hService, SERVICE_CONFIG_LAUNCH_PROTECTED, &info) == FALSE) {
            retval = GetLastError();
            LOG_F(ERROR, "ETW-TI: install_service: ChangeServiceConfig2 Error: %d", retval);
            return retval;
        }
    }

    //LOG_F(INFO, "[PPL_RUNNER] install_service: install_service: Created Service: %s", serviceCMD);
    //LOG_F(INFO, "[PPL_RUNNER] install_service: Run 'net start %s' to start the service", SERVICE_NAME);

    // Start service
    hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_START | SERVICE_QUERY_STATUS);
    if (hService == NULL) {
        retval = GetLastError();
        LOG_F(ERROR, "ETW-TI: OpenService failed, error: %d", retval);
        CloseServiceHandle(hSCManager);
        return retval;
    }
    bSuccess = StartService(hService, 0, NULL);
    if (!bSuccess) {
        retval = GetLastError();
        if (retval == ERROR_SERVICE_ALREADY_RUNNING) {
            LOG_F(WARNING, "ETW-TI: Service is already running");
        }
        else {
            LOG_F(ERROR, "ETW-TI: StartService failed, error: %d", retval);
        }
    }
    else {
        LOG_F(INFO, "ETW-TI: Service started successfully");
    }

    // Close handles
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return retval;
}


// No worky as no PPLy
DWORD remove_ppl_service() {
    DWORD retval = 0;
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    SERVICE_STATUS_PROCESS ssp;
    DWORD dwBytesNeeded;
    LOG_F(INFO, "ETW-TI: remove_service()");
    //LOG_F(INFO, "[REDEDR_PPL] remove_service: Stopping and Deleting Service %s...", SERVICE_NAME);

    // Get Handle to Service Manager and Service
    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
        retval = GetLastError();
        LOG_F(ERROR, "ETW-TI: remove_service: OpenSCManager Error: %d", retval);
        return retval;

    }
    hService = OpenService(hSCManager, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (hService == NULL) {
        retval = GetLastError();
        LOG_F(ERROR, "ETW-TI:  remove_service: OpenService Error: %d", retval);
        return retval;
    }

    // Get status of service
    if (!QueryServiceStatusEx(
        hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
        retval = GetLastError();
        LOG_F(ERROR, "ETW-TI: remove_service: QueryServiceStatusEx1 Error: %d", retval);
        return retval;
    }

    if (ssp.dwCurrentState != SERVICE_STOPPED) {
        // Send a stop code to the service.
        if (!ControlService(hService, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp)) {
            retval = GetLastError();
            LOG_F(ERROR, "ETW-TI: remove_service: ControlService(Stop) Error: %d", retval);
            return retval;
        }
        if (ssp.dwCurrentState != SERVICE_STOPPED) {
            // Wait for service to die
            Sleep(3000);
            if (!QueryServiceStatusEx(
                hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
                retval = GetLastError();
                LOG_F(ERROR, "ETW-TI: remove_service: QueryServiceStatusEx2 Error: %d", retval);
                return retval;
            }
            if (ssp.dwCurrentState != SERVICE_STOPPED) {
                retval = ssp.dwCurrentState;
                LOG_F(ERROR, "ETW-TI: remove_service: Waited but service still not stopped: %d", retval);
                return retval;
            }
        }
    }

    // Service stopped, now remove it
    if (!DeleteService(hService)) {
        retval = GetLastError();
        LOG_F(ERROR, "ETW-TI: remove_service: DeleteService Error: %d", retval);
        return retval;
    }

    LOG_F(INFO, "ETW-TI: remove_service: Deleted Service %ls", SERVICE_NAME);

    return retval;
}
