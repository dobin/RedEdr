#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "etwtihandler.h"
#include "logging.h"
#include "emitter.h"
#include "json.hpp"
#include "etw_krabs.h"
#include "process_resolver.h"


// Used for debug currently
unsigned int events_all = 0;
unsigned int events_processed = 0;


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
    if (!g_ProcessResolver.observe(processId)) {
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
