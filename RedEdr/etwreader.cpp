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

// See https://github.com/jdu2600/Etw-SyscallMonitor/tree/main/src/ETW for nice events


void event_callback_kernel_process(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
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

    int event_id = schema.event_id();
    /*
        1 ProcessStart
        2 ProcessStop
        3 ThreadStart
        4 ThreadStop?
        5 ImageLoad
        6 ImageUnload
        11 ProcessFreeze
    */
    if (event_id != 1 && event_id != 2 && event_id != 3 && event_id != 4 
        && event_id != 5 && event_id != 6 && event_id != 11) 
    {
        return;
    }

    std::string json_ret = KrabsEtwEventToJsonStr(record, schema);
    g_EventAggregator.NewEvent(json_ret);
}


void event_callback_audit_api(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
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

    int event_id = schema.event_id();

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
    if (event_id < 3 || event_id > 6) {
        return;
    }

    std::string json_ret = KrabsEtwEventToJsonStr(record, schema);
    g_EventAggregator.NewEvent(json_ret);
}


void event_callback_kernel_file(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);

    // This function(-chain) should be high performance, or we lose events.

    // This will get information about the process, which may be slow, if not
    // done beofore. It can be done before, e.g. when Kernel event arrived
    DWORD processId = record.EventHeader.ProcessId;
    Process* process = g_ProcessResolver.getObject(processId);
    if (process == NULL) {
        //return;
    }
    if (!g_ProcessResolver.observe(processId)) {
        return;
    }

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

    // 10 NameCreateInfo 
    // 30 CreateNewFileInfo
    

    int event_id = schema.event_id();
    if (event_id != 10 && event_id != 30) {
        return;
    }

    std::string json_ret = KrabsEtwEventToJsonStr(record, schema);
    g_EventAggregator.NewEvent(json_ret);
}


void event_callback_kernel_network(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
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
    int event_id = schema.event_id();
    if (event_id != 12 && event_id != 15 && event_id != 28 && event_id != 31
        && event_id != 42 && event_id != 43 && event_id != 58 && event_id != 59) 
    {
        return;
    }

    std::string json_ret = KrabsEtwEventToJsonStr(record, schema);
    g_EventAggregator.NewEvent(json_ret);
}


void event_callback_security_audit(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
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

    /*
    * TODO
    */
    int event_id = schema.event_id();
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
    process_provider.add_on_event_callback(event_callback_kernel_process);
    trace_user.enable(process_provider);
    
    krabs::provider<> auditapi_provider(L"Microsoft-Windows-Kernel-Audit-API-Calls");
    auditapi_provider.trace_flags(auditapi_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    auditapi_provider.add_on_event_callback(event_callback_audit_api);
    trace_user.enable(auditapi_provider);
    
    krabs::provider<> kernelfile_provider(L"Microsoft-Windows-Kernel-File");
    kernelfile_provider.trace_flags(kernelfile_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    kernelfile_provider.add_on_event_callback(event_callback_kernel_file);
    trace_user.enable(kernelfile_provider);

    krabs::provider<> kernelnetwork_provider(L"Microsoft-Windows-Kernel-Network");
    kernelnetwork_provider.trace_flags(kernelnetwork_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    kernelnetwork_provider.add_on_event_callback(event_callback_kernel_network);
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
