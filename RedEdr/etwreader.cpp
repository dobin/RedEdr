#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include <krabs.hpp>

#include "json.hpp"
#include "utils.h"
#include "etw_krabs.h"
#include "logging.h"

#include "event_aggregator.h"

#include "etwreader.h"
#include "process_resolver.h"
#include "config.h"



krabs::user_trace trace_user(L"RedEdrUser");


void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);

    // This function(-chain) should be high performance, or we lose events.

    // This will get information about the process, which may be slow, if not
    // done beofore. It can be done before, e.g. when Kernel event arrived
    DWORD processId = record.EventHeader.ProcessId;
    Process* process = g_ProcessResolver.getObject(processId);
    if (process == NULL) {
        return;
    }
    if (!g_ProcessResolver.observe(processId)) {
        return;
    }
    int opcode = schema.event_opcode();
    if (opcode == 98 || opcode == 99) {
        // temp:
        // PageFaultVirtualAlloc
		// PageFaultVirtualFree
        return;
    }

    std::string json_ret = KrabsEtwEventToJsonStr(record, schema);
    g_EventAggregator.NewEvent(json_ret);
}


BOOL InitializeEtwReader(std::vector<HANDLE>& threads) {
    LOG_A(LOG_INFO, "!ETW: Started Thread");
    HANDLE thread = CreateThread(NULL, 0, TraceProcessingThread, NULL, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "ETW: Could not start thread");
        return FALSE;
    }
	threads.push_back(thread);
    return TRUE;
}


DWORD WINAPI TraceProcessingThread(LPVOID param) {
    krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
    process_provider.trace_flags(process_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    process_provider.add_on_event_callback(event_callback);
    trace_user.enable(process_provider);
    
    krabs::provider<> auditapi_provider(L"Microsoft-Windows-Kernel-Audit-API-Calls");
    auditapi_provider.trace_flags(auditapi_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    auditapi_provider.add_on_event_callback(event_callback);
    trace_user.enable(auditapi_provider);
    
    krabs::provider<> securityauditing_provider(L"Microsoft-Windows-Security-Auditing");
    securityauditing_provider.trace_flags(securityauditing_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    securityauditing_provider.add_on_event_callback(event_callback);
    trace_user.enable(securityauditing_provider);

    // Blocking, stopped with trace.stop()
    trace_user.start();

    LOG_A(LOG_INFO, "!ETW: Thread Finished...");
    return 0;
}


void EtwReaderStopAll() {
    trace_user.stop();
}
