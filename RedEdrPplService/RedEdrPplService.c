#include <stdio.h>
#include <Windows.h>

#include "../Shared/common.h"
#include "utils.h"
#include "consumer.h"
#include "emitter.h"
#include "control.h"


SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;


void service_exit() {
    log_message(L"Shutdown");

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


VOID WINAPI service_ctrl_handler(DWORD ctrlCode)
{
    // As we are PPL, this cannot be invoked really?
    switch (ctrlCode)
    {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;
        service_exit();
        break;

    default:
        break;
    }
}


// Real service main()
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    DWORD retval = 0;
    log_message(L"Service Start");

    // Register our service control handler with the SCM
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, service_ctrl_handler);
    if (g_StatusHandle == NULL)
    {
        retval = GetLastError();
        log_message(L"ServiceMain: Registerservice_ctrl_handler Error: %d", retval);
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
    start_control();

    // Set the service status to RUNNING after initialization is complete
    g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
    g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    g_ServiceStatus.dwCheckPoint = 0;
    g_ServiceStatus.dwWaitHint = 0;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Service loop or logic here
    while (g_ServiceStatus.dwCurrentState == SERVICE_RUNNING) {
        // Start collecting
        initialize_etwti_reader(); // BLOCKS atm
        break;
    }

    log_message(L"ServiceMain: Finished");
    service_exit();

    return;
}


// Setup the service (from main)
DWORD service_entry()
{
    DWORD retval = 0;
    SERVICE_TABLE_ENTRY serviceTable[] =
    {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };

    if (StartServiceCtrlDispatcher(serviceTable) == FALSE)
    {
        retval = GetLastError();
        log_message(L"service_entry: StartServiceCtrlDispatcher error: %d", retval);
        return retval;
    }

    return retval;
}


DWORD main(INT argc, CHAR** argv)
{
    log_message(L"Start RedEdr PPL Service");
    service_entry();
    return 0;
}
