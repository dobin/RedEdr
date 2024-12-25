
#include "logging.h"
#include "config.h"
#include "json.hpp"

#include "event_augmenter.h"
#include "mem_static.h"


/* Augments the Event JSON with additional information
 * Depends on MemStatic to resolve addresses
 */


void AugmentEvent(nlohmann::json& j) {
	AugmentEventWithMemAddrInfo(j);
}


void AugmentEventWithMemAddrInfo(nlohmann::json& j) {
    // InjectedDLL: callstack
    if (j.contains("callstack") && j["callstack"].is_array()) {
        for (auto& callstack_entry : j["callstack"]) {
            if (callstack_entry.contains("addr")) {
                uint64_t addr = callstack_entry["addr"].get<uint64_t>();
                std::string symbol = g_MemStatic.ResolveStr(addr);
                callstack_entry["addr_info"] = symbol;

                if (g_config.debug) {
                    LOG_A(LOG_INFO, "Addr 0x%llx Symbol: %s",
                        addr,
                        symbol.c_str());
                }
            }
        }
    }

    // ETW: stack_trace
    if (j.contains("stack_trace") && j["stack_trace"].is_array()) {
        for (auto& callstack_entry : j["stack_trace"]) {
            if (callstack_entry.contains("addr")) {
                uint64_t addr = callstack_entry["addr"].get<uint64_t>();
                std::string symbol = g_MemStatic.ResolveStr(addr);
                callstack_entry["addr_info"] = symbol;

                if (g_config.debug) {
                    LOG_A(LOG_INFO, "Addr 0x%llx Symbol: %s",
                        addr,
                        symbol.c_str());
                }
            }
        }
    }
}


BOOL EventHasOurDllCallstack(nlohmann::json& j) {
    // For ETW
    unsigned int occurences = 0;
    if (j.contains("stack_trace") && j["stack_trace"].is_array()) {
        for (auto& callstack_entry : j["stack_trace"]) {
            if (callstack_entry.contains("addr_info")) {
                if (callstack_entry["addr_info"].get<std::string>().find("RedEdrDll.dll") != std::string::npos) {
                    occurences += 1;

                    // ONE RedEdrDll.dll entry if hooked
                    if (occurences == 2) {
                        return TRUE;
                    }
                }
            }
        }
    }
    return FALSE;
}


