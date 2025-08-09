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
#include "etwtihandler.h"
#include "piping.h"

#include <krabs.hpp>


krabs::user_trace trace_ppl(L"RedEdrPpl");


// Blocking
void StartEtwtiReader() {
    // https://docs.google.com/spreadsheets/d/1d7hPRktxzYWmYtfLFaU_vMBKX2z98bci0fssTYyofdo/edit?gid=180219839#gid=180219839
    /*
        1	THREATINT_ALLOCVM_REMOTE
        2	THREATINT_PROTECTVM_REMOTE
        3	THREATINT_MAPVIEW_REMOTE
        4	THREATINT_QUEUEUSERAPC_REMOTE
        5	THREATINT_SETTHREADCONTEXT_REMOTE
        6	THREATINT_ALLOCVM_LOCAL
        7	THREATINT_PROTECTVM_LOCAL
        8	THREATINT_MAPVIEW_LOCAL
        11	THREATINT_READVM_LOCAL
        12	THREATINT_WRITEVM_LOCAL
        13	THREATINT_READVM_REMOTE
        14	THREATINT_WRITEVM_REMOTE
        15	THREATINT_SUSPEND_THREAD
        16	THREATINT_RESUME_THREAD
        17	THREATINT_SUSPEND_PROCESS
        18	THREATINT_RESUME_PROCESS
        19	THREATINT_FREEZE_PROCESS
        20	THREATINT_THAW_PROCESS
        21	THREATINT_ALLOCVM_REMOTE_KERNEL_CALLER
        22	THREATINT_PROTECTVM_REMOTE_KERNEL_CALLER
        23	THREATINT_MAPVIEW_REMOTE_KERNEL_CALLER
        24	THREATINT_QUEUEUSERAPC_REMOTE_KERNEL_CALLER
        25	THREATINT_SETTHREADCONTEXT_REMOTE_KERNEL_CALLER
        26	THREATINT_ALLOCVM_LOCAL_KERNEL_CALLER
        27	THREATINT_PROTECTVM_LOCAL_KERNEL_CALLER
        28	THREATINT_MAPVIEW_LOCAL_KERNEL_CALLER
        29	THREATINT_DRIVER_OBJECT_LOAD
        30	THREATINT_DRIVER_OBJECT_UNLOAD
        31	THREATINT_DEVICE_OBJECT_LOAD
        32	THREATINT_DEVICE_OBJECT_UNLOAD
    */

    LOG_A(LOG_INFO, "Preparing to read from ETW-TI");
    krabs::provider<> ti_provider(L"Microsoft-Windows-Threat-Intelligence");
    ti_provider.trace_flags(ti_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    ti_provider.add_on_event_callback(event_callback);
    trace_ppl.enable(ti_provider);

    LOG_A(LOG_INFO, "Start reading from ETW-TI");
    // Blocking, stopped with trace.stop()
    trace_ppl.start();
}


void ShutdownEtwtiReader() {
    LOG_A(LOG_INFO, "Stop Reading from ETW-TI");
    trace_ppl.stop();
}

