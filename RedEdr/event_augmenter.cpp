
#include "logging.h"
#include "config.h"
#include "json.hpp"

#include "event_augmenter.h"


/* Augments the Event JSON with additional information
 * Depends on MemStatic to resolve addresses
 */


void AugmentEvent(nlohmann::json& j, Process *process) {
	AugmentEventWithMemAddrInfo(j, process);
}


void AugmentEventWithMemAddrInfo(nlohmann::json& j, Process *process) {
    // InjectedDLL: callstack
    if (j.contains("callstack") && j["callstack"].is_array()) {
        for (auto& callstack_entry : j["callstack"]) {
            if (callstack_entry.contains("addr")) {
                uint64_t addr = callstack_entry["addr"].get<uint64_t>();
                std::string symbol = process->memStatic.ResolveStr(addr);
                callstack_entry["addr_info"] = symbol;

                if (g_Config.debug) {
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
                std::string symbol = process->memStatic.ResolveStr(addr);
                callstack_entry["addr_info"] = symbol;

                if (g_Config.debug) {
                    LOG_A(LOG_INFO, "Addr 0x%llx Symbol: %s",
                        addr,
                        symbol.c_str());
                }
            }
        }
    }
}

