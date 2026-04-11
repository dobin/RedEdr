#pragma once

#include <evntrace.h>
#include <vector>
#include <string>

#include <krabs.hpp>

void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context);
void event_callback_defendertrace(const EVENT_RECORD& record, const krabs::trace_context& trace_context);

extern volatile BOOL g_DoDefenderTrace;
void SetDefenderTraceConfig(BOOL enabled, const std::vector<std::string>& targetNames);