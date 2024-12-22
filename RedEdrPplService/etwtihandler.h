#pragma once

#include <windows.h>
#include <evntrace.h>
#include <tdh.h>

#include <krabs.hpp>

void enable_consumer(BOOL e);
void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context);