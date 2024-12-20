
#include "logging.h"
#include "config.h"
#include "json.hpp"

#include "process_query.h"
#include "event_augmenter.h"
#include "mem_static.h"


/* Augments the Event JSON with additional information
 * Depends on MemStatic to resolve addresses
 */


void AugmentEvent(nlohmann::json& j) {
	AugmentEventWithMemAddrInfo(j);
}


void AugmentEventWithMemAddrInfo(nlohmann::json& j) {
    if (j.contains("callstack") && j["callstack"].is_array()) {
        for (auto& callstack_entry : j["callstack"]) {
            if (callstack_entry.contains("addr")) {
                uint64_t addr = callstack_entry["addr"].get<uint64_t>();
                std::string symbol = g_MemStatic.ResolveStr(addr);
                callstack_entry["addr_info"] = symbol;

                // log
                if (g_config.debug) {
                    LOG_A(LOG_INFO, "Addr 0x%llx Symbol: %s",
                        addr,
                        symbol.c_str());
                }
            }
        }
    }
}


