#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include <krabs.hpp>
#include "json.hpp"
#include "utils.h"
#include "process_query.h"


std::string KrabsEtwEventToJsonStr(const EVENT_RECORD& record, krabs::schema schema) {
    krabs::parser parser(schema);

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
    std::string d = wstring2string(c);
    j["event"] = d;

    j["opcode_id"] = schema.event_opcode();
    j["provider_name"] = std::to_string(record.EventHeader.ProviderId);

    // Iterate over all properties defined in the schema
    for (const auto& property : parser.properties()) {
        try {
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
            std::string jsonKey = wstring2string((std::wstring&)propertyName);

            // Special cases
            if (propertyName == L"ProtectionMask" || propertyName == L"LastProtectionMask") {
                uint32_t protection_mask = parser.parse<uint32_t>(propertyName);
                j[jsonKey] = getMemoryRegionProtect(protection_mask);
                continue;
            }

            switch (propertyType) {
            case TDH_INTYPE_UINT32:
                j[jsonKey] = (uint32_t) parser.parse<uint32_t>(propertyName);
                //j[jsonKey + "_vartype"] = "TDH_INTYPE_UINT32";
                break;

            case TDH_INTYPE_UINT64:
                j[jsonKey] = (uint64_t) parser.parse<uint64_t>(propertyName);
                //j[jsonKey + "_vartype"] = "TDH_INTYPE_UINT64";
                break;

            case TDH_INTYPE_UNICODESTRING:
            {
                std::wstringstream ss;
                ss << parser.parse<std::wstring>(propertyName);
                std::string s = wstring2string((std::wstring&)ss.str());
                j[jsonKey] = s;
            }
                break;

            case TDH_INTYPE_ANSISTRING:
                j[jsonKey] = parser.parse<std::string>(propertyName);
                break;

            case TDH_INTYPE_POINTER:
                j[jsonKey] = (uint64_t) parser.parse<PVOID>(propertyName);
                //j[jsonKey + "_vartype"] = "TDH_INTYPE_POINTER";
                break;

            case TDH_INTYPE_FILETIME:
            {
                // Not a PFILETIME!
                FILETIME fileTime = parser.parse<FILETIME>(propertyName);

                // As int
                ULARGE_INTEGER uli;
                uli.LowPart = fileTime.dwLowDateTime;
                uli.HighPart = fileTime.dwHighDateTime;

                j[jsonKey] = uli.QuadPart;
                break;
            }

            default:
                j[jsonKey] = "unsupported";
                break;
            }

        }
        catch (const std::exception& ex) {
            std::wcout << L"Failed to parse property: " << ex.what() << L"\n";
        }
    }

    // Callstack
    j["stack_trace"] = nlohmann::json::array();
    auto stack_trace = schema.stack_trace();
    int idx = 0;
    for (auto& return_address : stack_trace)
    {
        // Only add non-kernelspace addresses
        if (return_address < 0xFFFF080000000000) {
            j["stack_trace"].push_back({ 
                { "addr", return_address}, 
                { "idx", idx }
            });
            idx++;
        }
    }

    return j.dump();
}
