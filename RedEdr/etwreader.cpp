#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include <krabs.hpp>
#include "json.hpp"

#include "event_aggregator.h"
#include "logging.h"
#include "etwreader.h"
#include "process_resolver.h"
#include "config.h"
#include "utils.h"


krabs::user_trace trace_user(L"RedEdrUser");


void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    // This function should be high performance, or we lose events.

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

    // To construct a JSON, we use nlohmann::json, which works in std::string
    // (utf-8). We need to convert all data several times.

    nlohmann::json j;

	j["type"] = "etw";
	j["time"] = static_cast<__int64>(record.EventHeader.TimeStamp.QuadPart);
	j["pid"] = record.EventHeader.ProcessId;
	j["thread_id"] = record.EventHeader.ThreadId;

    // Construct the event string, like "ImageLoad"
    std::wstring a = std::wstring(schema.task_name());
    std::wstring b = std::wstring(schema.opcode_name());
    std::wstring c = a + b;
    std::string d = wstring_to_utf8(c);
	j["event"] = d;

    j["opcode_id"] = schema.event_opcode();
	j["provider_name"] = std::to_string(record.EventHeader.ProviderId);

    // Iterate over all properties defined in the schema
    for (const auto& property : parser.properties()) {
        try {
            std::wstringstream ss;

            // Get the name and type of the property
            const std::wstring& propertyName = property.name();
            const auto propertyType = property.type();

            /*
            * Reserved1":"0","Reserved2":"0","Reserved3":"0","Reserved4":"0",
            * "SignatureLevel":"(Unsupported type)\n","SignatureType":"(Unsupported type)\n
            */
			if (wstring_starts_with(propertyName, L"Reserved") || wstring_starts_with(propertyName, L"Signature")) {
				continue;
			}

            switch (propertyType) {
            case TDH_INTYPE_UINT32:
                ss << parser.parse<uint32_t>(propertyName);
                break;
            case TDH_INTYPE_UINT64:
                ss << parser.parse<uint64_t>(propertyName);
                break;
            case TDH_INTYPE_UNICODESTRING:
                ss << parser.parse<std::wstring>(propertyName);
                break;
            case TDH_INTYPE_ANSISTRING:
                ss << utf8_to_wstring(parser.parse<std::string>(propertyName));
                break;
            case TDH_INTYPE_POINTER:  // hex
                ss << parser.parse<PVOID>(propertyName);
                break;
            case TDH_INTYPE_FILETIME:
            {
                // Not a PFILETIME!
                FILETIME fileTime = parser.parse<FILETIME>(propertyName);

                // As int
                ULARGE_INTEGER uli;
                uli.LowPart = fileTime.dwLowDateTime;
                uli.HighPart = fileTime.dwHighDateTime;
                ss << uli.QuadPart;

                // As string
                /*SYSTEMTIME stUTC, stLocal;
                FileTimeToSystemTime(&fileTime, &stUTC);
                SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
                ss << stLocal.wYear << L"/" << stLocal.wMonth << L"/" << stLocal.wDay << L" "
                    << stLocal.wHour << L":" << stLocal.wMinute << L":" << stLocal.wSecond;
                */

                break;
            }

            default:
                ss << L"(Unsupported type)\n";
                break;
            }

			// Add the key/value as UTF-8 to the JSON
            std::string key_2 = wstring_to_utf8((std::wstring&) propertyName);
            std::string value_2 = wstring_to_utf8((std::wstring&) ss.str());
            j[key_2] = value_2;
        }
        catch (const std::exception& ex) {
            std::wcout << L"Failed to parse property: " << ex.what() << L"\n";
        }
    }

    // Callstack
    auto stack_trace = schema.stack_trace();
    for (auto& return_address : stack_trace)
    {
        j["stack_trace"] += return_address;
    }

    // Generate the JSON, and convert it back to wstring...
    std::string json_ret = j.dump();
    std::wstring json_retw = utf8_to_wstring(json_ret);
    g_EventAggregator.do_output(json_retw);
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
