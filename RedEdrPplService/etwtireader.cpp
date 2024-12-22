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

