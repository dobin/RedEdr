#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <string>

#include "etwtihandler.h"
#include "logging.h"
#include "emitter.h"
#include "json.hpp"
#include "etw_krabs.h"
#include "process_resolver.h"
#include "utils.h"


// Used for debug currently
unsigned int events_all = 0;
unsigned int events_processed = 0;

volatile BOOL g_DoDefenderTrace = FALSE;
static std::vector<std::string> g_DefenderTraceTargetNames;

void SetDefenderTraceConfig(BOOL enabled, const std::vector<std::string>& targetNames) {
    g_DoDefenderTrace = enabled;
    g_DefenderTraceTargetNames = targetNames;
}

void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    // This function should be high performance, or we lose events.
    events_all++;
    if (events_all == 10) {
        LOG_W(LOG_INFO, L"Handler: Processed %u ETW-TI events so far. Seems to work. ", events_all);
    }

    // Check if we should follow this process
    DWORD processId = record.EventHeader.ProcessId;

    Process* process = g_ProcessResolver.getObject(processId);
    if (process == NULL) {
        LOG_A(LOG_WARNING, "ETW: No process object for pid %lu", processId);
        return;
    }
    if (!process->observe) {
        return;
    }

    events_processed++;
    if (events_processed == 10) {
        LOG_W(LOG_INFO, L"Handler: Processed %u accepted ETW-TI events so far. Seems to work. ", events_processed);
    }

	nlohmann::json j = KrabsEtwEventToJsonStr(record, schema);
	j["process_name"] = process->name;
    SendEmitterPipe((char*)j.dump().c_str());
}


// Handle ETW-TI events from msmpeng.exe (Windows Defender) for defender trace
void event_callback_defendertrace(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    if (!g_DoDefenderTrace) {
        return;
    }

    krabs::schema schema(record, trace_context.schema_locator);

    // Resolve source process — must be msmpeng.exe
    DWORD processId = record.EventHeader.ProcessId;
    Process* process = g_ProcessResolver.getObject(processId);
    if (process == NULL) {
        return;
    }
    if (!contains_case_insensitive(process->name, "msmpeng")) {
        return;
    }

    // Convert ETW to JSON
    nlohmann::json j = KrabsEtwEventToJsonStr(record, schema);
    j["process_name"] = process->name;

    // Check if destination is one of our target processes
    if (j.contains("pid") && !j["pid"].is_null()) {
        DWORD targetPid = j["pid"].get<DWORD>();

        Process* targetProcess = g_ProcessResolver.getObject(targetPid);
        if (targetProcess == NULL) {
            return;
        }
        if (targetProcess->observe) {
            SendEmitterPipe((char*)j.dump().c_str());
        }
    }
    // Mostly TargetProcessId, see https://blog.deeb.ch/posts/windows-telemetry/
    else if (j.contains("targetprocessid") && !j["targetprocessid"].is_null()) {
        DWORD targetPid = j["targetprocessid"].get<DWORD>();

        Process* targetProcess = g_ProcessResolver.getObject(targetPid);
        if (targetProcess == NULL) {
            return;
        }
        if (targetProcess->observe) {
            SendEmitterPipe((char*)j.dump().c_str());
        }
    }
    // Check if filename matches any of our target processes
    else if (j.contains("filename") && !j["filename"].is_null()) {
        std::string filename = j["filename"].get<std::string>();
        for (const auto& targetProcessName : g_DefenderTraceTargetNames) {
            if (ends_with_case_insensitive(filename, targetProcessName)) {
                SendEmitterPipe((char*)j.dump().c_str());
                break;
            }
        }
    }
    // Check if name matches any of our target processes
    else if (j.contains("name") && !j["name"].is_null()) {
        std::string name = j["name"].get<std::string>();
        for (const auto& targetProcessName : g_DefenderTraceTargetNames) {
            if (ends_with_case_insensitive(name, targetProcessName)) {
                SendEmitterPipe((char*)j.dump().c_str());
                break;
            }
        }
    }
}
