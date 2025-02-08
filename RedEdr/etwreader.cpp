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
    // See https://github.com/jdu2600/Etw-SyscallMonitor/tree/main/src/ETW for nice events

    /*
        1 ProcessStart
        2 ProcessStop
        3 ThreadStart
        4 ThreadStop?
        5 ImageLoad
        6 ImageUnload
        11 ProcessFreeze
    */
    krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
	std::vector<unsigned short> process_event_ids = { 1, 2, 3, 4, 5, 6, 11 };
    krabs::event_filter process_filter(process_event_ids);
    process_provider.trace_flags(process_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    process_filter.add_on_event_callback(event_callback);
	process_provider.add_filter(process_filter);
    trace_user.enable(process_provider);
    
    /*
        Event ID 1: PspLogAuditSetLoadImageNotifyRoutineEvent(kernel)
        Event ID 2: PspLogAuditTerminateRemoteProcessEvent

        Event ID 3: NtCreateSymbolicLink
        Event ID 4: PspSetContextThreadInternal
        Event ID 5: PspLogAuditOpenProcessEvent
        Event ID 6: PspLogAuditOpenThreadEvent

        Event ID 7: IoRegisterLastChanceShutdownNotification(kernel)
        Event ID 8: IoRegisterShutdownNotification(kernel)
    */
    krabs::provider<> auditapi_provider(L"Microsoft-Windows-Kernel-Audit-API-Calls");
    std::vector<unsigned short> auditapi_event_ids = { 3, 4, 5, 6 };
    krabs::event_filter auditapi_filter(process_event_ids);
    auditapi_provider.trace_flags(auditapi_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    auditapi_filter.add_on_event_callback(event_callback);
	auditapi_provider.add_filter(auditapi_filter);
    trace_user.enable(auditapi_provider);
    
    /*
        10 NameCreate
        30 CreateNewFile

        17 SetInformation
        //22 QueryInformation
        19 Rename
        29 Rename9
        25 DirNotify
        23 FSCTL
        26 DeletePath
        27 RenamePath
        28 SetLinkPath
        31 SetSecurity
        32 QuerySecurity
        33 SetEA
        34 QueryEA
    */
    krabs::provider<> kernelfile_provider(L"Microsoft-Windows-Kernel-File");
    std::vector<unsigned short> kernelfile_event_ids = { 10, 30 };
    krabs::event_filter kernelfile_filter(process_event_ids);
    kernelfile_provider.trace_flags(kernelfile_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    kernelfile_filter.add_on_event_callback(event_callback);
	kernelfile_provider.add_filter(kernelfile_filter);
    trace_user.enable(kernelfile_provider);

    /*
        12 KERNEL_NETWORK_TASK_TCPIPConnectionattempted
        15 KERNEL_NETWORK_TASK_TCPIPConnectionaccepted
        28 KERNEL_NETWORK_TASK_TCPIPConnectionattempted
        31 KERNEL_NETWORK_TASK_TCPIPConnectionaccepted

        42 KERNEL_NETWORK_TASK_UDPIPDatasentoverUDPprotocol
        43 KERNEL_NETWORK_TASK_UDPIPDatareceivedoverUDPprotocol
        58 KERNEL_NETWORK_TASK_UDPIPDatasentoverUDPprotocol
        59 KERNEL_NETWORK_TASK_UDPIPDatareceivedoverUDPprotocol
    */
    krabs::provider<> kernelnetwork_provider(L"Microsoft-Windows-Kernel-Network");
    std::vector<unsigned short> kernelnetwork_event_ids = { 12, 15, 28, 31, 42, 43, 58, 59 };
    krabs::event_filter kernelnetwork_filter(process_event_ids);
    kernelnetwork_provider.trace_flags(kernelnetwork_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    kernelnetwork_filter.add_on_event_callback(event_callback);
	kernelnetwork_provider.add_filter(kernelnetwork_filter);
    trace_user.enable(kernelnetwork_provider);
    
    /* Temporarily disabled as it doesnt seem to work really and has not interesting events
    krabs::provider<> securityauditing_provider(L"Microsoft-Windows-Security-Auditing");
    securityauditing_provider.trace_flags(securityauditing_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    securityauditing_provider.add_on_event_callback(event_callback);
    trace_user.enable(securityauditing_provider);
    */

    // Blocking, stopped with trace.stop()
    trace_user.start();

    LOG_A(LOG_INFO, "!ETW: Thread Finished...");
    return 0;
}


void EtwReaderStopAll() {
    trace_user.stop();
}
