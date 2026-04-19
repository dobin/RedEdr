#include <windows.h>
#include <winioctl.h>
#include "../Shared/common.h"

#include "logging.h"
#include "config.h"
#include "kernelinterface.h"
#include "utils.h"


// KernelInterface: Functions to interact with the kernel driver (load/unload, enable/disable)


BOOL ConfigureKernelDriver(int enable) {
    HANDLE hDevice = INVALID_HANDLE_VALUE;
    wchar_t* targetW = nullptr;

    if (g_Config.targetProcessNames.empty()) {
        LOG_A(LOG_ERROR, "Kernel: No target process specified for kernel driver");
        return FALSE;
    }
    std::string target = g_Config.targetProcessNames[0];
    
    try {
        hDevice = CreateFile(L"\\\\.\\RedEdr",
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hDevice == INVALID_HANDLE_VALUE) {
            LOG_A(LOG_ERROR, "Kernel: Failed to open device. Error: %d", GetLastError());
            return FALSE;
        }
        
        targetW = string2wcharAlloc(target);
        if (targetW == nullptr) {
            LOG_A(LOG_ERROR, "Kernel: Failed to convert target string to wchar_t");
            CloseHandle(hDevice);
            return FALSE;
        }
    MY_DRIVER_DATA kernel_config = { 0 };
    if (enable) {
        size_t targetLen = wcslen(targetW);
        if (targetLen >= sizeof(kernel_config.filename) / sizeof(wchar_t)) {
            LOG_A(LOG_ERROR, "Kernel: Target filename too long");
            delete[] targetW;
            CloseHandle(hDevice);
            return FALSE;
        }
        wcscpy_s(kernel_config.filename, sizeof(kernel_config.filename) / sizeof(wchar_t), targetW);
        kernel_config.enable_dll_injection = g_Config.do_hook;
        kernel_config.enable = enable;

        if (g_Config.do_etwti) {
            kernel_config.enable_etwti_events = 1;
            if (g_Config.do_defendertrace) {
                kernel_config.enable_etwti_events_defender = 1;
            } else {
                kernel_config.enable_etwti_events_defender = 0;
            }
        } else {
            kernel_config.enable_etwti_events = 0;
            kernel_config.enable_etwti_events_defender = 0;
        }

        // Log
        LOG_A(LOG_INFO, "Kernel: enable=%d, dll_injection=%d, etwti_events=%d, etwti_events_defender=%d, filename=%ls",
            kernel_config.enable,
            kernel_config.enable_dll_injection,
            kernel_config.enable_etwti_events,
            kernel_config.enable_etwti_events_defender,
            kernel_config.filename);
    }
    else {
        kernel_config.enable = 0;        
        kernel_config.enable_etwti_events = 0;
        kernel_config.enable_etwti_events_defender = 0;
    }
    delete[] targetW;  // Free allocated memory
    char buffer_incoming[KRN_CONFIG_LEN] = { 0 }; // Answer will be "OK" or "FAIL" so this is enough
    DWORD bytesReturned = 0;
    BOOL success = DeviceIoControl(hDevice,
        IOCTL_MY_IOCTL_CODE,
            (LPVOID)&kernel_config,
            (DWORD)sizeof(kernel_config),
            buffer_incoming,
            sizeof(buffer_incoming), // this should get the correct size
            &bytesReturned,
            NULL);
        if (!success) {
            LOG_A(LOG_ERROR, "Kernel: DeviceIoControl failed. Error: %d", GetLastError());
            CloseHandle(hDevice);
            return FALSE;
        }

        if (bytesReturned == 0) {
            LOG_A(LOG_ERROR, "Kernel: DeviceIoControl returned no data");
            CloseHandle(hDevice);
            return FALSE;
        }

        // Ensure null termination
        buffer_incoming[min(bytesReturned, sizeof(buffer_incoming) - 1)] = '\0';

        if (strcmp(buffer_incoming, "OK") == 0) {
            LOG_A(LOG_INFO, "Kernel: Kernel Driver enabling/disabling (%d) ok", enable);
            CloseHandle(hDevice);
            return TRUE;
        }
        else {
            LOG_A(LOG_ERROR, "Kernel: Kernel Driver enabling/disabling (%d) failed. Response: %s", enable, buffer_incoming);
            CloseHandle(hDevice);
            return FALSE;
        }
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "Kernel: Exception in ConfigureKernelDriver: %s", e.what());
        if (targetW) delete[] targetW;
        if (hDevice != INVALID_HANDLE_VALUE) CloseHandle(hDevice);
        return FALSE;
    }
}


BOOL LoadKernelDriver() {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    LPCWSTR driverName = g_Config.driverName;
    LPCWSTR driverPath = g_Config.driverPath;
    BOOL ret = FALSE;

    // Open the Service Control Manager
    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        LOG_A(LOG_ERROR, "Kernel: OpenSCManager failed. Error: %lu", GetLastError());
        return FALSE;
    }

    // Create the service (driver)
    hService = CreateService(
        hSCManager,              // SCM handle
        driverName,              // Name of the service
        driverName,              // Display name
        SERVICE_ALL_ACCESS,      // Desired access
        SERVICE_KERNEL_DRIVER,   // Service type (kernel driver)
        SERVICE_DEMAND_START,    // Start type (on demand)
        SERVICE_ERROR_NORMAL,    // Error control type
        driverPath,              // Path to the driver executable
        NULL,                    // No load ordering group
        NULL,                    // No tag identifier
        NULL,                    // No dependencies
        NULL,                    // LocalSystem account
        NULL                     // No password
    );

    if (!hService) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            LOG_A(LOG_INFO, "Kernel: Service already exists. Opening existing service...");
            hService = OpenService(hSCManager, driverName, SERVICE_ALL_ACCESS);
            if (!hService) {
                LOG_A(LOG_ERROR, "Kernel: OpenService failed. Error: %lu", GetLastError());
                ret = FALSE;
                goto cleanup;
            }
        }
        else {
            LOG_A(LOG_ERROR, "Kernel: CreateService failed. Error: %lu", GetLastError());
            ret = FALSE;
            goto cleanup;
        }
    }

    // Start the service (load the driver)
    if (!StartService(hService, 0, NULL)) {
        if (GetLastError() != ERROR_SERVICE_ALREADY_RUNNING) {
            LOG_A(LOG_ERROR, "Kernel: StartService failed. Error: %lu", GetLastError());
            ret = FALSE;
            goto cleanup;
        }
        else {
            ret = TRUE;  // Service already running should be success
            LOG_A(LOG_INFO, "Kernel: Service already running.");
        }
    }
    else {
        ret = TRUE;
        LOG_A(LOG_INFO, "Kernel: Service started successfully.");
    }

cleanup:
    if (hService) {
        if (!ret) {
            // Only delete service if we failed to start it
            DeleteService(hService);
        }
        CloseServiceHandle(hService);
    }
    if (hSCManager) {
        CloseServiceHandle(hSCManager);
    }

    return ret;
}


BOOL UnloadKernelDriver() {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS status;
    LPCWSTR driverName = g_Config.driverName;
    BOOL ret = FALSE;

    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        LOG_A(LOG_ERROR, "Kernel: OpenSCManager failed. Error: %lu", GetLastError());
        return FALSE;
    }

    hService = OpenService(hSCManager, driverName, SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
    if (!hService) {
        LOG_A(LOG_ERROR, "Kernel: OpenService failed. Error: %lu", GetLastError());
        ret = FALSE;
        goto cleanup;
    }

    if (ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        LOG_A(LOG_INFO, "Kernel: Service stopped successfully.");
        ret = TRUE;
    }
    else if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
        LOG_A(LOG_INFO, "Kernel: Service is not running.");
        ret = TRUE;
    }
    else {
        LOG_A(LOG_ERROR, "Kernel: ControlService failed. Error: %lu", GetLastError());
        ret = FALSE;
        goto cleanup;
    }

    if (!DeleteService(hService)) {
        LOG_A(LOG_ERROR, "Kernel: DeleteService failed. Error: %lu", GetLastError());
        ret = FALSE;
        goto cleanup;
    }
    else {
        LOG_A(LOG_INFO, "Kernel: Service deleted successfully.");
    }

cleanup:
    if (hService) CloseServiceHandle(hService);
    if (hSCManager) CloseServiceHandle(hSCManager);

    return ret;
}
