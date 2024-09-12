#include <stdio.h>
#include <Windows.h>

#include "../Shared/common.h"
#include "consumer.h"
#include "emitter.h"
#include "control.h"

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;

VOID log_message(WCHAR* format, ...)
{
    WCHAR message[MAX_BUF_SIZE];

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = _vsnwprintf_s(message, MAX_BUF_SIZE, MAX_BUF_SIZE, format, arg_ptr);
    va_end(arg_ptr);

    OutputDebugString(message);
    OutputDebugString(L"\n");
    wprintf(message);
    wprintf(L"\n");
    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, message);
}


// Function to enable a privilege for the current process
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        log_message(L"LookupPrivilegeValue error: %d", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    // Enable the privilege or disable all privileges.
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) {
        log_message(L"AdjustTokenPrivileges error: %d", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        log_message(L"The token does not have the specified privilege.");
        return FALSE;
    }

    return TRUE;
}
BOOL makeMeSeDebug() {
    // Get a handle to the current process token
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        log_message(L"OpenProcessToken failed: %d", GetLastError());
        return FALSE;
    }

    // Enable SeDebugPrivilege
    if (!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
        log_message(L"Failed to enable SeDebugPrivilege.");
        CloseHandle(hToken);
        return FALSE;
    }

    CloseHandle(hToken);

    log_message(L"--[ Enable SE_DEBUG: OK");
    return TRUE;
}


void myshutdown() {
    log_message(L"[PPL_RUNNER] Shutdown");

    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwWaitHint = 0;

    // Inform the SCM that the service is stopping
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Perform necessary cleanup before stopping
    // ... (e.g., stop threads, close handles, etc.)

    // Indicate that the service has stopped
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

    // Exit the service
    ExitProcess(0);

    /*DWORD retval = 0;
    g_ServiceStatus.dwControlsAccepted = 0;
    g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    g_ServiceStatus.dwWin32ExitCode = 0;
    g_ServiceStatus.dwCheckPoint = 4;
    if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
    {
        retval = GetLastError();
        log_message(L"[PPL_RUNNER] ServiceMain: SetServiceStatus(StopPending) Error: %d\n", retval);
        return;
    }*/

    // Tell the service controller we are stopped
// So we can be run again
/*
g_ServiceStatus.dwControlsAccepted = 0;
g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
g_ServiceStatus.dwWin32ExitCode = retval;
g_ServiceStatus.dwServiceSpecificExitCode = retval;
g_ServiceStatus.dwCheckPoint = 0;
if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
{
    retval = GetLastError();
    log_message(L"[PPL_RUNNER] ServiceMain: SetServiceStatus(Stopped) Error: %d\n", retval);
    return;
}*/
}


VOID WINAPI service_ctrl_handler(DWORD ctrlCode)
{
    log_message(L"[PPL_RUNNER] service_ctrl_handler");
    switch (ctrlCode)
    {
    case SERVICE_CONTROL_STOP:
        if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;
        myshutdown();
        break;

    default:
        break;
    }
}


VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    DWORD retval = 0;
    log_message(L"[PPL_RUNNER] ServiceMain: Starting");

    // Register our service control handler with the SCM
    g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, service_ctrl_handler);
    if (g_StatusHandle == NULL)
    {
        retval = GetLastError();
        log_message(L"[PPL_RUNNER] ServiceMain: Registerservice_ctrl_handler Error: %d", retval);
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

    // Simulate long initialization
    //Sleep(2000);  // Simulate some initialization delay
    
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

        // Simulate some work
        //Sleep(1000);
    }

    log_message(L"[PPL_RUNNER] ServiceMain: Finished??");
    myshutdown();

    return;
}


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
        log_message(L"[PPL_RUNNER] service_entry: StartServiceCtrlDispatcher error: %d", retval);
        return retval;
    }

    return retval;
}


BOOL WINAPI ConsoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        log_message(L"--! Ctrl-c detected, performing shutdown");
        shutdown_etwti_reader();
        return TRUE; // Indicate that we handled the signal
    default:
        return FALSE; // Let the next handler handle the signal
    }
}


DWORD main(INT argc, CHAR** argv)
{
    DWORD retval = 0;
    log_message(L"[PPL_RUNNER] main: Start");

    // If started as service
    service_entry();

    /*
    // Ctrl+C
    if (!SetConsoleCtrlHandler(ConsoleCtrlHandler, TRUE)) {
        log_message(L"--( Failed to set control handler");
        return 1;
    }
    
    makeMeSeDebug();

    // Control: Pipe to read from (thread)
    // Consumer: ETW consumer (callback)
    // Emitter: Pipe to RedEdr (invoked)

    // Start the control channel
    start_control();

    // Start collecting
    initialize_etwti_reader();

    // Simulate service
    while (TRUE) {
        Sleep(10000);
        log_message(L"Sleep");
    }*/

    return retval;
}
