#include <windows.h>
#include <evntrace.h>
#include <tdh.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include "logging.h"
#include "etwtihandler.h"
#include "objcache.h"
#include "emitter.h"
#include "utils.h"
#include "json.hpp"
#include "etw_krabs.h"


BOOL enabled_consumer = FALSE;

unsigned int events_all = 0;
unsigned int events_processed = 0;


void enable_consumer(BOOL e) {
    LOG_W(LOG_INFO, L"Handler: Enable: %d", e);
    enabled_consumer = e;
}


void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    // This function should be high performance, or we lose events.
    events_all++;
    if (events_all == 10) {
        LOG_W(LOG_INFO, L"Handler: Processed %u ETW-TI events so far", events_processed);
    }

    if (!enabled_consumer) {
        return;
    }

    // Check if we should follow this process
    DWORD processId = record.EventHeader.ProcessId;
    struct my_hashmap* obj = get_obj(processId);
    if (!obj->value) {
        return;
    }

    events_processed++;
    if (events_processed == 10) {
        LOG_W(LOG_INFO, L"Handler: Processed %u accepted ETW-TI events so far", events_processed);
    }

	std::string json_retw = KrabsEtwEventToJsonStr(record, schema);
    SendEmitterPipe((char*)json_retw.c_str());
}
