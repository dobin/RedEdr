#pragma once

#include <evntrace.h>

#include <krabs.hpp>

void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context);