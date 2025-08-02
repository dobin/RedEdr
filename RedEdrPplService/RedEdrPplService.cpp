#include <stdio.h>
#include <Windows.h>

#include "../Shared/common.h"
#include "etwtireader.h"
#include "emitter.h"
#include "control.h"
#include "logging.h"
#include "objcache.h"

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
BOOL                  g_ServiceStopping = FALSE;


void ShutdownService() {
    LOG_W(LOG_INFO, L"Shutdown initiated");
    
    g_ServiceStopping = TRUE;

    // Stopping
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwWaitHint = 5000; // Give 5 seconds for cleanup
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Perform necessary cleanup before stopping
    StopControl();
    ShutdownEtwtiReader();
    clean_obj(); // Clean up object cache, target name, and mutex

    // Stopped
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    
    LOG_W(LOG_INFO, L"Service shutdown complete");
}


VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    switch (ctrlCode)
    {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;
        LOG_W(LOG_INFO, L"Service stop requested");
        ShutdownService();
        break;

    case SERVICE_CONTROL_INTERROGATE:
        // Return current status
        SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
        break;

    default:
        LOG_W(LOG_INFO, L"Unhandled service control code: %d", ctrlCode);
        break;
    }
}


// Real service main()
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    DWORD retval = 0;
    LOG_W(LOG_INFO, L"Service Start");

    // Register our service control handler with the SCM
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);
    if (g_StatusHandle == NULL)
    {
        retval = GetLastError();
        LOG_W(LOG_ERROR, L"ServiceMain: RegisterServiceCtrlHandler Error: %d", retval);
        return;
    }

    // Set the service status to START_PENDING
    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 3000;  // Wait hint of 3 seconds
    
    if (!SetServiceStatus(g_StatusHandle, &g_ServiceStatus)) {
        LOG_W(LOG_ERROR, L"ServiceMain: Failed to set service status");
        return;
    }

    // Initialize object cache
    objcache_init();

    // Start Control thread which will listen on a pipe for commands
    StartControl();

    // Set the service status to RUNNING after initialization is complete
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    
    if (!SetServiceStatus(g_StatusHandle, &g_ServiceStatus)) {
        LOG_W(LOG_ERROR, L"ServiceMain: Failed to set running status");
        ShutdownService();
        return;
    }

    LOG_W(LOG_INFO, L"Service is now running");

    // Service main loop
    while (g_ServiceStatus.dwCurrentState == SERVICE_RUNNING && !g_ServiceStopping) {
        // Start collecting - this may block
        StartEtwtiReader();
        
        // If we get here, ETW reader has stopped, check if we should continue
        if (!g_ServiceStopping) {
            LOG_W(LOG_INFO, L"ServiceMain: ETW reader stopped, waiting before restart...");
            Sleep(5000); // Wait before retry to avoid rapid restart loop
        }
    }

    LOG_W(LOG_INFO, L"ServiceMain: Exiting main loop");
    
    if (!g_ServiceStopping) {
        ShutdownService();
    }
}


// Setup the service (from main)
DWORD ServiceEntry()
{
    DWORD retval = 0;
    SERVICE_TABLE_ENTRY serviceTable[] =
    {
        {const_cast<LPWSTR>(SERVICE_NAME), (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcher(serviceTable) == FALSE)
    {
        retval = GetLastError();
        LOG_W(LOG_ERROR, L"ServiceEntry: StartServiceCtrlDispatcher error: %d", retval);
        return retval;
    }

    return retval;
}


int main(INT argc, CHAR** argv)
{
    LOG_A(LOG_INFO, "Starting RedEdr PPL Service %s", REDEDR_VERSION);
    
    DWORD result = ServiceEntry();
    if (result != 0) {
        LOG_A(LOG_ERROR, "Service failed to start, error: %d", result);
    }
    
    LOG_A(LOG_INFO, "RedEdr PPL Service terminated");
    return result;
}
