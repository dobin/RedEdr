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
#include "../RedEdr/json.hpp"


BOOL enabled_consumer = FALSE;


void enable_consumer(BOOL e) {
    LOG_W(LOG_INFO, L"Consumer: Enable: %d", e);
    enabled_consumer = e;
}


void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    // This function should be high performance, or we lose events.

    if (!enabled_consumer) {
        return;
    }

    // Check if we should follow this process
    DWORD processId = record.EventHeader.ProcessId;
    struct my_hashmap* obj = get_obj(processId);
    if (!obj->value) {
        return;
    }

    /////////////////////////////////////////

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
            std::string key_2 = wstring_to_utf8((std::wstring&)propertyName);
            std::string value_2 = wstring_to_utf8((std::wstring&)ss.str());
            j[key_2] = value_2;
        }
        catch (const std::exception& ex) {
            std::wcout << L"Failed to parse property: " << ex.what() << L"\n";
        }
    }

    // Callstack
    auto stack_trace = schema.stack_trace();
    j["stack_trace"] = {};
    for (auto& return_address : stack_trace)
    {
        // Only add non-kernelspace addresses
        if (return_address < 0xFFFF080000000000) {
            j["stack_trace"] += { {"addr", return_address} };
        }
    }

    // Generate the JSON, and convert it back to wstring...
    std::string json_ret = j.dump();
    std::wstring json_retw = utf8_to_wstring(json_ret);
    
    /////////////////////////////////////////

    SendEmitterPipe((wchar_t*)json_retw.c_str());
}
