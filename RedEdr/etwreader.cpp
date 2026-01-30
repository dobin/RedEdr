#include <Windows.h>
#include <iostream>
#include <vector>
#include <krabs.hpp>
#include "json.hpp"

#include "etw_krabs.h"
#include "logging.h"
#include "event_aggregator.h"
#include "etwreader.h"
#include "process_resolver.h"
#include "config.h"
#include "utils.h"


krabs::user_trace trace_user(L"RedEdrUser");

BOOL is_trace_in_progress = FALSE; // currently unused
HANDLE threadReadynessEtw = NULL; // ready to start tracing


void trace_in_progress(BOOL use) {
    is_trace_in_progress = use;
}


// Handle ETW events for process monitoring
// - Where ProcessId of EventHeader is our target process
void event_callback_process(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    try {
        krabs::schema schema(record, trace_context.schema_locator);
        
		// Check if we observe the process which emitted this event
        DWORD processId = record.EventHeader.ProcessId;
        Process* process = g_ProcessResolver.getObject(processId);
        if (process == NULL) {
            LOG_A(LOG_WARNING, "ETW: No process object for pid %lu", processId);
            return;
        }
        if (!process->observe) {
            return;
        }

        // Convert ETW to JSON
        nlohmann::json j = KrabsEtwEventToJsonStr(record, schema);
        j["etw_process"] = process->name;

        // Emit event
        g_EventAggregator.NewEvent(j.dump());
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "ETW event_callback exception: %s", e.what());
    }
    catch (...) {
        LOG_A(LOG_ERROR, "ETW event_callback unknown exception");
    }
}


// Handle ETW events for antimalware monitoring
// - Where "pid" or "filename" or "name" matches our target processes
void event_callback_antimalware(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    //if (!is_trace_in_progress) {
	//	return;
	//}

    try {
        krabs::schema schema(record, trace_context.schema_locator);
        // Convert ETW to JSON
        nlohmann::json j = KrabsEtwEventToJsonStr(record, schema);

        // Resolve (source) process name
        DWORD processId = record.EventHeader.ProcessId;
        Process* process = g_ProcessResolver.getObject(processId);
        if (process == NULL) {
            LOG_A(LOG_WARNING, "ETW: No process object for pid %lu", processId);
            return;
        }
        j["etw_process"] = process->name;

        // Check if destination is one of our target processes
        if (j.contains("pid") && !j["pid"].is_null()) {
            DWORD targetPid = j["pid"].get<DWORD>();

			// check if we observe the target process
            Process* targetProcess = g_ProcessResolver.getObject(targetPid);
            if (targetProcess == NULL) {
                LOG_A(LOG_WARNING, "ETW: No target process object for pid %lu", targetPid);
                return;
            }
            if (targetProcess->observe) {
                // Emit event
                g_EventAggregator.NewEvent(j.dump());
			}
        }
		// Check if filename matches any of our target processes
        // Cache MOACLookup 36
        else if (j.contains("filename") && !j["filename"].is_null()) {
            std::string filename = j["filename"].get<std::string>();
            for (const auto& targetProcessName : g_Config.targetProcessNames) {
                if (ends_with_case_insensitive(filename, targetProcessName)) {
                    // Emit event
                    g_EventAggregator.NewEvent(j.dump());
                    break;
                }
            }
        }
		// Check if name matches any of our target processes
        // ExpensiveOperationTaskExpensiveOperationBegin 43
        // ExpensiveOperationTaskExpensiveOperationEnd 67
        else if (j.contains("name") && !j["name"].is_null()) {
            std::string filename = j["name"].get<std::string>();
            for (const auto& targetProcessName : g_Config.targetProcessNames) {
                if (ends_with_case_insensitive(filename, targetProcessName)) {
                    // Emit event
                    g_EventAggregator.NewEvent(j.dump());
                    break;
                }
            }
        }
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "ETW event_callback exception: %s", e.what());
    }
    catch (...) {
        LOG_A(LOG_ERROR, "ETW event_callback unknown exception");
    }
}


BOOL InitializeEtwReader(std::vector<HANDLE>& threads) {
    threadReadynessEtw = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (threadReadynessEtw == NULL) {
        LOG_A(LOG_ERROR, "ETW: Failed to create event for thread readiness");
        return FALSE;
    }

    HANDLE thread = CreateThread(NULL, 0, TraceProcessingThread, NULL, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "ETW: Could not start thread");
        if (threadReadynessEtw != NULL) {
            CloseHandle(threadReadynessEtw);
            threadReadynessEtw = NULL;
        }
        return FALSE;
    }
    
    // Wait for the thread (ETW) to be fully initialized before returning
    WaitForSingleObject(threadReadynessEtw, INFINITE);
    
    LOG_A(LOG_INFO, "!ETW: Started Thread (handle %p)", thread);
    threads.push_back(thread);
    return TRUE;
}


DWORD WINAPI TraceProcessingThread(LPVOID param) {
    try {
        // See https://github.com/jdu2600/Etw-SyscallMonitor/tree/main/src/ETW for nice events

        /*
            1 ProcessStart
            2 ProcessStop
            3 ThreadStart
            4 ThreadStop
            5 ImageLoad
            6 ImageUnload
            11 ProcessFreeze
        */
        krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
        std::vector<unsigned short> process_event_ids = { 1, 2, 3, 4, 5, 6, 11 };
        krabs::event_filter process_filter(process_event_ids);
        process_provider.trace_flags(process_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        process_filter.add_on_event_callback(event_callback_process);
        process_provider.add_filter(process_filter);
        trace_user.enable(process_provider);
        LOG_A(LOG_INFO, "ETW: Microsoft-Windows-Kernel-Process (1, 2, 3, 4, 5, 6, 11)");
        
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
        krabs::event_filter auditapi_filter(auditapi_event_ids);
        auditapi_provider.trace_flags(auditapi_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        auditapi_filter.add_on_event_callback(event_callback_process);
        auditapi_provider.add_filter(auditapi_filter);
        trace_user.enable(auditapi_provider);
        LOG_A(LOG_INFO, "ETW: Microsoft-Windows-Kernel-Audit-API-Calls (3, 4, 5, 6)");
        
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
        krabs::event_filter kernelfile_filter(kernelfile_event_ids);
        kernelfile_provider.trace_flags(kernelfile_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        kernelfile_filter.add_on_event_callback(event_callback_process);
        kernelfile_provider.add_filter(kernelfile_filter);
        trace_user.enable(kernelfile_provider);
        LOG_A(LOG_INFO, "ETW: Microsoft-Windows-Kernel-File (10, 30)");

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
        krabs::event_filter kernelnetwork_filter(kernelnetwork_event_ids);
        kernelnetwork_provider.trace_flags(kernelnetwork_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        kernelnetwork_filter.add_on_event_callback(event_callback_process);
        kernelnetwork_provider.add_filter(kernelnetwork_filter);
        trace_user.enable(kernelnetwork_provider);
        LOG_A(LOG_INFO, "ETW: Microsoft-Windows-Kernel-Network (12, 15, 28, 31, 42, 43, 58, 59)");

        /* https://docs.google.com/spreadsheets/d/1d7hPRktxzYWmYtfLFaU_vMBKX2z98bci0fssTYyofdo/edit?gid=0#gid=0
            4624	An account was successfully logged on.
            4625	An account failed to log on.
            4627	Group membership information.
            4634	An account was logged off
            4647	User initiated logoff.
            4648	A logon was attempted using explicit credentials.
            4656	A handle to an object was requested.
            4657	A registry value was modified.
            4660	An object was deleted.
            4661	A handle to an object was requested.
            4662	An operation was performed on an object.
            4663	An attempt was made to access an object.
            4664	An attempt was made to create a hard link.
            4672	Special privileges assigned to new logon.
            4673	A privileged service was called.
            4674	An operation was attempted on a privileged object.
            4688	A new process has been created.
            4689	A process has exited.
            4690	An attempt was made to duplicate a handle to an object.
            4696	A primary token was assigned to process.
            4697	A service was installed in the system.
            4698	A scheduled task was created.
            4699	A scheduled task was deleted.
            4700	A scheduled task was enabled.
            4701	A scheduled task was disabled.
            4702	A scheduled task was updated.
            4703	A user right was adjusted.
            4741	A computer account was created.
            4742	A computer account was changed.
            4743	A computer account was deleted.
            4768	A Kerberos authentication ticket (TGT) was requested.
            4769	A Kerberos service ticket was requested.
            4770	A Kerberos service ticket was renewed.
            4771	Kerberos pre-authentication failed.
            4798	A user's local group membership was enumerated.
            5145	A network share object was checked to see whether client can be granted desired access.
            5379	Credential Manager credentials were read.
        */
        // Temporarily disabled as it doesnt seem to work really and has not interesting events
        /* 
        krabs::provider<> securityauditing_provider(L"Microsoft-Windows-Security-Auditing");
        securityauditing_provider.trace_flags(securityauditing_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
        securityauditing_provider.add_on_event_callback(event_callback_process);
        trace_user.enable(securityauditing_provider);
        */

		// Microsoft-Antimalware-Engine
        // We currently observe all event id's, and filter in the callback
        krabs::provider<> antimalwareengine_provider(L"Microsoft-Antimalware-Engine");
        if (g_Config.do_antimalwareengine) {
            antimalwareengine_provider.add_on_event_callback(event_callback_antimalware);
            trace_user.enable(antimalwareengine_provider);
            LOG_A(LOG_INFO, "ETW: Microsoft-Antimalware-Engine (all)");
        }

        LOG_A(LOG_INFO, "ETW: All providers configured, ready to start collecting");
        
        // Signal that the thread is fully initialized
        SetEvent(threadReadynessEtw);

        // Blocking, stopped with trace.stop()
        trace_user.start();
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "ETW TraceProcessingThread exception: %s", e.what());
    }
    catch (...) {
        LOG_A(LOG_ERROR, "ETW TraceProcessingThread unknown exception");
    }

    LOG_A(LOG_INFO, "!ETW: Thread finished");
    return 0;
}


void EtwReaderStopAll() {
    trace_user.stop();
    
    // Clean up event handle
    if (threadReadynessEtw != NULL) {
        CloseHandle(threadReadynessEtw);
        threadReadynessEtw = NULL;
    }
}
