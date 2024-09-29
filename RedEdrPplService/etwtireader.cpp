#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <combaseapi.h>
#include <iostream>
#include <tdh.h>
#include <stdio.h>
#include <stdlib.h>
#include <evntrace.h>

#include <sddl.h>

#include "emitter.h"
#include "objcache.h"
#include "logging.h"
#include "etwtireader.h"
#include "etwconsumer.h"
#include "etwtihandler.h"
#include "piping.h"

#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "tdh.lib")


wchar_t* SessionName = (wchar_t *) L"RedEdrPplServiceEtwTiReader";
EtwConsumer etwConsumer;


void StartEtwtiReader() {
    if (1) {
        if (!etwConsumer.SetupEtw(
            0,
            L"{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}",
            &EventRecordCallbackTi,
            L"Microsoft-Windows-Threat-Intelligence",
            SessionName
        )) {
            LOG_W(LOG_ERROR, L"Consumer: Problem with: Microsoft-Windows-Threat-Intelligence");
        }
    }
    else {
        // For testing only:
        if (!etwConsumer.SetupEtw(
            0,
            L"{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}",
            &EventRecordCallbackKernelProcess,
            L"Microsoft-Windows-Kernel-Process",
            SessionName
        )) {
            LOG_W(LOG_ERROR, L"Consumer: Problem with: Microsoft-Windows-Kernel-Process");
        }
    }

    if (!etwConsumer.StartEtw()) {
        LOG_W(LOG_ERROR, L"Consumer: Problem with: Microsoft-Windows-Kernel-Process");
    }

    return;
}


BOOL ShutdownEtwtiReader() {
    LOG_W(LOG_INFO, L"Consumer: Stopping EtwTracing");
    etwConsumer.StopEtw();
    return TRUE;
}

