#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

#include <krabs.hpp>

#include "eventproducer.h"
#include "logging.h"
#include "etwreader.h"
#include "processcache.h"
#include "config.h"

#include "json.hpp"


krabs::kernel_trace trace_kernel(L"RedEdrKernel");
krabs::user_trace trace_user(L"RedEdrUser");

#include <locale>
#include <codecvt>


std::string wstring_to_utf8_2(const std::wstring& wide_string) {
    if (wide_string.empty()) {
        return {};
    }

    // Determine the size needed for the UTF-8 buffer
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) {
        throw std::runtime_error("Failed to calculate size for UTF-8 string.");
    }

    // Allocate the buffer and perform the conversion
    std::string utf8_string(size_needed - 1, '\0'); // Exclude the null terminator
    WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, &utf8_string[0], size_needed, nullptr, nullptr);

    return utf8_string;
}


std::wstring utf8_to_wstring(const std::string& str) {
    if (str.empty()) {
        return {};
    }

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), nullptr, 0);
    std::wstring result(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), &result[0], size_needed);
    return result;
}

bool starts_with2(const std::wstring& str, const std::wstring& prefix) {
    if (str.size() < prefix.size()) {
        return false;
    }
    return str.compare(0, prefix.size(), prefix) == 0;
}


void event_callback(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    DWORD processId = record.EventHeader.ProcessId;
    if (!g_ProcessCache.observe(processId)) {
        return;
    }
    int opcode = schema.event_opcode();
    if (opcode == 98 || opcode == 99) {
        // temp
        // PageFaultVirtualAlloc
		// PageFaultVirtualFree
        return;
    }

    nlohmann::json j;
/*
    output << L"{";
    output << L"\"type\":\"etw\",";
    output << L"\"time\":" << static_cast<__int64>(eventRecord->EventHeader.TimeStamp.QuadPart) << L",";
    output << L"\"pid\":" << eventRecord->EventHeader.ProcessId << L",";
    output << L"\"thread_id\":" << eventRecord->EventHeader.ThreadId << L",";
    output << L"\"event\":\"" << eventName << L"\",";
    output << L"\"provider_name\":\"" << (eventInfo->ProviderNameOffset ? (PCWSTR)((PBYTE)eventInfo + eventInfo->ProviderNameOffset) : L"Unknown") << L"\",";
    */

	j["type"] = "etw";
	j["time"] = static_cast<__int64>(record.EventHeader.TimeStamp.QuadPart);
	j["pid"] = record.EventHeader.ProcessId;
	j["thread_id"] = record.EventHeader.ThreadId;

    // FUUUUUUUUUUUUUUUUUUUUUUCK THIS SHIT OMFG
    std::wstring a = std::wstring(schema.task_name());
    std::wstring b = std::wstring(schema.opcode_name());
    std::wstring c = a + b;
    std::string d = wstring_to_utf8_2(c);
	j["event"] = d;

    j["opcode_id"] = schema.event_opcode();
    
	j["provider_name"] = std::to_string(record.EventHeader.ProviderId);
    
    //j["event"] = schema.event_name();
	//j["provider_name"] = schema.provider_name();

    /* 
    {"DefaultBase":"Value: 00007FFC682D0000",
    "FileName":"Value: \\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll",
    "ImageBase":"Value: 00007FFC682D0000",
    "ImageChecksum":"Value: 2198146","ImageSize":"Value: 0000000000217000",
    "ProcessId":"Value: 6352",
    "Reserved0":"Value: (Unsupported type)\n","Reserved1":"Value: 0",
    "Reserved2":"Value: 0","Reserved3":"Value: 0","Reserved4":"Value: 0",
    "SignatureLevel":"Value: (Unsupported type)\n","SignatureType":"Value: (Unsupported type)\n",
    "TimeDateStamp":"Value: 3875757754","id":"2cb15d1d-5fc1-11d2-abe1-00a0c911f518",
    "opcode":2,
    
    "opcode_name":"UnLoad","task_name":"Image"}
    */
	//j["id"] = std::to_string(record.EventHeader.ProviderId);
	//j["task_name"] = schema.task_name();
	//j["opcode"] = schema.event_opcode();
	//j["opcode_name"] = schema.opcode_name();

    /*
    std::wstringstream ss;
    ss << L"{";
    ss << L"\"id:\":\"" << std::to_wstring(record.EventHeader.ProviderId) << "\",";
    //ss << L"\"provider\":\"" << schema.provider_name() << "\",";
    //ss << L"\"event_name\":\"" << schema.event_name() << "\",";
    ss << L"\"task_name\":\"" << schema.task_name() << "\",";
    ss << L"\"opcode\":\"" << schema.event_opcode() << "\",";
    ss << L"\"opcode_name\":\"" << schema.opcode_name() << "\"";
    ss << L"}";
    */

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
			if (starts_with2(propertyName, L"Reserved") || starts_with2(propertyName, L"Signature")) {
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
                FILETIME fileTime = *parser.parse<PFILETIME>(propertyName);
                SYSTEMTIME stUTC, stLocal;
                FileTimeToSystemTime(&fileTime, &stUTC);
                SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);
                ss << stLocal.wYear << L"/" << stLocal.wMonth << L"/" << stLocal.wDay << L" "
                    << stLocal.wHour << L":" << stLocal.wMinute << L":" << stLocal.wSecond;
                break;
            }

            default:
                ss << L"(Unsupported type)\n";
                break;
            }

            // FUCK ME SIDEWAYS
            std::string key_2 = wstring_to_utf8_2((std::wstring&) propertyName);
            std::string value_2 = wstring_to_utf8_2((std::wstring&) ss.str());
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

    // GOD FUCKING DAMNIT
    std::string json_fuck = j.dump();
    std::wstring json_fuck_2 = utf8_to_wstring(json_fuck);
    g_EventProducer.do_output(json_fuck_2);
}


void event_callback_stack(const EVENT_RECORD& record, const krabs::trace_context& trace_context) {
    krabs::schema schema(record, trace_context.schema_locator);
    krabs::parser parser(schema);

    //if (schema.event_opcode() == 1) {
        //auto pid = parser.parse<uint32_t>(L"ProcessID");
        //auto image_name = parser.parse<std::wstring>(L"ImageName");
        auto stack_trace = schema.stack_trace();

        std::wcout << std::endl << schema.task_name();
        //std::wcout << L" ProcessID=" << pid;
        //std::wcout << L" ImageName=" << image_name;
        std::wcout << std::endl << L"Call Stack:" << std::endl;
        for (auto& return_address : stack_trace)
        {
            std::wcout << L"   0x" << std::hex << return_address << std::endl;
        }
    //}
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
    // OK
    krabs::provider<> process_provider(L"Microsoft-Windows-Kernel-Process");
    //process_provider.any(0x10);
    process_provider.trace_flags(process_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    process_provider.add_on_event_callback(event_callback);
    trace_user.enable(process_provider);
    
    // OK
    krabs::provider<> auditapi_provider(L"Microsoft-Windows-Kernel-Audit-API-Calls");
    //auditapi_provider.any(0x10);
    auditapi_provider.trace_flags(auditapi_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    auditapi_provider.add_on_event_callback(event_callback);
    trace_user.enable(auditapi_provider);
    
    // BROKEN? No messages
    krabs::provider<> securityauditing_provider(L"Microsoft-Windows-Security-Auditing");
    //securityauditing_provider.any(0x10);
    securityauditing_provider.trace_flags(securityauditing_provider.trace_flags() | EVENT_ENABLE_PROPERTY_STACK_TRACE);
    securityauditing_provider.add_on_event_callback(event_callback);
    trace_user.enable(securityauditing_provider);


    /*
         *    krabs::trace trace;
         *    // Adjust SE_SYSTEM_PROFILE_NAME token privilege through AdjustTokenPrivileges(...)
         *    // to enable stack tracing (not done in this example). Then:
         *    STACK_TRACING_EVENT_ID event_id = {0};
         *    event_id.EventGuid = krabs::guids::perf_info;
         *    event_id.Type = 46; // SampleProfile
         *    trace.open();
         *    trace.set_trace_information(TraceStackTracingInfo, &event_id, sizeof(STACK_TRACING_EVENT_ID));
         *    krabs::kernel_provider stack_walk_provider(EVENT_TRACE_FLAG_PROFILE, krabs::guids::stack_walk);
         *    trace.enable(stack_walk_provider);
         *    trace.process();
    */

    
    /*
    //krabs::kernel_provider stack_walk_provider(EVENT_TRACE_FLAG_PROFILE, krabs::guids::stack_walk);
    krabs::kernel_provider stack_walk_provider(EVENT_TRACE_FLAG_PROFILE, krabs::guids::image_load);

    CLASSIC_EVENT_ID    event[1] = { 0 }; 
    event[0].EventGuid = krabs::guids::image_load; 
    event[0].Type = EVENT_TRACE_TYPE_END;
    //event[0].Type = EVENT_TRACE_TYPE_LOAD;

    trace_kernel.open();
    trace_kernel.set_trace_information(TraceStackTracingInfo, &event, sizeof(event));
   
	stack_walk_provider.add_on_event_callback(event_callback_stack);
    
    trace_kernel.enable(stack_walk_provider);
    trace_kernel.process();
    */

    /*
    //krabs::kernel_provider provider(SOME_GUID, SOME_ULONG_MASK_VALUE);
    krabs::kernel_provider my_provider(0, krabs::guids::ob_trace);
    trace_kernel.enable(my_provider);
    trace_kernel.set_trace_information();
    */

    /*
    krabs::kernel::thread_dispatch_provider thread_dispatch_provider;
    krabs::kernel::image_load_provider image_load_provider;
    krabs::kernel::dpc_provider dpc_provider;
    krabs::kernel::process_provider process_provider;
    krabs::kernel::system_call_provider system_call_provider;
    krabs::kernel::thread_provider thread_provider;
    krabs::kernel::vamap_provider vamap_provider;
    krabs::kernel::virtual_alloc_provider virtual_alloc_provider;

    thread_dispatch_provider.add_on_event_callback(event_callback);
    image_load_provider.add_on_event_callback(event_callback);
    dpc_provider.add_on_event_callback(event_callback);
    process_provider.add_on_event_callback(event_callback);
    system_call_provider.add_on_event_callback(event_callback);
    thread_provider.add_on_event_callback(event_callback);
    vamap_provider.add_on_event_callback(event_callback);
    virtual_alloc_provider.add_on_event_callback(event_callback);

    trace.enable(thread_dispatch_provider);
    trace.enable(image_load_provider);
    trace.enable(dpc_provider);
    trace.enable(process_provider);
    trace.enable(system_call_provider);
    trace.enable(thread_provider);
    trace.enable(vamap_provider);
    trace.enable(virtual_alloc_provider);
    */

    // Blocking, stopped with trace.stop()
    trace_user.start();

    LOG_A(LOG_INFO, "ETW: Thread Finished...");
    return 0;
}


void EtwReaderStopAll() {
    trace_user.stop();
}
