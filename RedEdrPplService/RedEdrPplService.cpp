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

LPWSTR lServiceName = (wchar_t*) SERVICE_NAME;


void ShutdownService() {
    LOG_W(LOG_INFO, L"Shutdown");

    // Stopping
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Perform necessary cleanup before stopping

    // Stopped
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Exit the process
    ExitProcess(0);
}


VOID WINAPI ServiceCtrlHandler(DWORD ctrlCode)
{
    // As we are PPL, this cannot be invoked really?
    switch (ctrlCode)
    {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;
        ShutdownService();
        break;

    default:
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
        LOG_W(LOG_INFO, L"ServiceMain: Registerservice_ctrl_handler Error: %d", retval);
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
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Start Control thread which will listen on a pipe for commands
    StartControl();

    // Set the service status to RUNNING after initialization is complete
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Service loop or logic here
    while (g_ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        // Start collecting
        StartEtwtiReader(); // BLOCKS atm
        break;
    }

    LOG_W(LOG_INFO, L"ServiceMain: Finished");
    ShutdownService();

    return;
}


// Setup the service (from main)
DWORD ServiceEntry()
{
    DWORD retval = 0;
    SERVICE_TABLE_ENTRY serviceTable[] =
    {
        {lServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    objcache_init();

    if (StartServiceCtrlDispatcher(serviceTable) == FALSE)
    {
        retval = GetLastError();
        LOG_W(LOG_INFO, L"service_entry: StartServiceCtrlDispatcher error: %d", retval);
        return retval;
    }

    return retval;
}


DWORD main(INT argc, CHAR** argv)
{
    LOG_W(LOG_INFO, L"Start RedEdr PPL Service 0.2");
    ServiceEntry();

    if (0) {
        objcache_init();
        StartControl();
        StartEtwtiReader(); // BLOCKS atm
        ShutdownService();
    }

    return 0;
}
