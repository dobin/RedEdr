#include <iostream>
#include <sstream>
#include <vector>

#include "process_resolver.h"
#include "process_query.h"
#include "event_processor.h"
#include "event_aggregator.h"
#include "event_augmenter.h"
#include "utils.h"
#include "config.h"
#include "../Shared/common.h"
#include "logging.h"

/* event_processor.c: Gets new events from EventAggregator and processes them
 *   Keeps stats
 *   Keeps copy of all events
 *   Augments events with additional information
 *   Query process for more information
 */


EventProcessor g_EventProcessor;


EventProcessor::EventProcessor() {
    //init();
}

void EventProcessor::init() {
    json_entries.clear();

	num_kernel = 0;
	num_etw = 0;
	num_etwti = 0;
	num_dll = 0;
    event_count = 0;
    GenerateNewTraceId();

    // Add meta data
	nlohmann::json j;
	j["type"] = "meta";
    j["func"] = "init";
	j["date"] = get_time_for_file();
    j["version"] = REDEDR_VERSION;
	j["trace_id"] = trace_id;

	j["do_etw"] = g_Config.do_etw;
	j["do_etwti"] = g_Config.do_etwti;
	j["do_hook"] = g_Config.do_hook;
	j["do_hook_callstack"] = g_Config.do_dllinjection_ucallstack;
	    
	j["targets"] = g_Config.targetProcessNames;
    json_entries.push_back(j);
}


void EventProcessor::LogInitialProcessInfo(Process *process) {
    // Log: Peb Info
    ProcessPebInfoRet processPebInfoRet = process->processPebInfoRet;
    try {
        nlohmann::json j;
		j["pid"] = process->id;
        j["type"] = "process_query";
        j["func"] = "peb";
        j["time"] = get_time();
        j["id"] = process->id;
        j["parent_pid"] = processPebInfoRet.parent_pid;
        j["image_path"] = processPebInfoRet.image_path;
        j["commandline"] = processPebInfoRet.commandline;
        j["working_dir"] = processPebInfoRet.working_dir;
        j["is_debugged"] = processPebInfoRet.is_debugged;
        j["is_protected_process"] = processPebInfoRet.is_protected_process;
        j["is_protected_process_light"] = processPebInfoRet.is_protected_process_light;
        j["image_base"] = processPebInfoRet.image_base;
        g_EventAggregator.NewEvent(j.dump());
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "EventProcessor: Error creating PEB info JSON: %s", e.what());
    }

    // Log: Loaded Modules Info
    try {
        std::vector<ProcessLoadedDll> processLoadedDlls = process->processLoadedDlls;
        nlohmann::json jDlls;
        jDlls["func"] = "loaded_dll";
        jDlls["type"] = "process_query";
        jDlls["time"] = get_time();
        jDlls["pid"] = process->id;
        jDlls["dlls"] = {};
        for (auto dllEntry : processLoadedDlls) {
            jDlls["dlls"] += {
                {"addr", dllEntry.dll_base},
                {"size", dllEntry.size},
                {"name", dllEntry.name}
            };
        }
        std::string jsonStr = jDlls.dump();
        remove_all_occurrences_case_insensitive(jsonStr, "C:\\\\Windows\\\\system32\\\\");
        g_EventAggregator.NewEvent(jsonStr);
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "EventProcessor: Error enumerating modules: %s", e.what());
    }
}


void EventProcessor::AnalyzeEventJson(nlohmann::json& j) {
    try {
        j["id"] = json_entries.size();
        j["trace_id"] = trace_id;

        // Sanity checks
        if (!j.contains("type")) {
            LOG_A(LOG_WARNING, "No type? %s", j.dump().c_str());
            return;
        }
        if (!j.contains("pid")) {
            LOG_A(LOG_WARNING, "No pid? %s", j.dump().c_str());
            return;
        }

        // Stats (for UI)
        EventStats(j);

        Process* process = g_ProcessResolver.getObject(j["pid"].get<DWORD>());
        if (process == nullptr) {
            // Should not happen
            LOG_A(LOG_WARNING, "EventProcessor: Failed to get process object for pid %lu", j["pid"].get<DWORD>());
            return;
        }

        // Check if we need to gather the detailed information about the process
        // If yes (not done before), do it and log it
        if (! process->augmented) {
            process->AugmentInfo();
            process->augmented = true;
            LogInitialProcessInfo(process);
        }

        // Augment the JSON Event with memory info
        AugmentEventWithMemAddrInfo(j, process);

        // Print Event
        PrintEvent(j);

        // Has to be at the end as we dont store reference
        json_entries.push_back(j);
        event_count++;
    }
    catch (const nlohmann::json::exception& e) {
        LOG_A(LOG_ERROR, "JSON error in AnalyzeEventJson: %s", e.what());
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "Error in AnalyzeEventJson: %s", e.what());
    }

    return;
}


void EventProcessor::AnalyzeEventStr(std::string eventStr) {
    nlohmann::json j;
    try
    {
        j = nlohmann::json::parse(eventStr);
    }
    catch (const nlohmann::json::exception& e)
    {
        LOG_A(LOG_WARNING, "JSON Parser Exception msg: %s", e.what());
        LOG_A(LOG_WARNING, "JSON Parser Exception event: %s", eventStr.c_str());
        return;
    }

    AnalyzeEventJson(j);
}


void EventProcessor::AnalyzeNewEvents(std::vector<std::string> events) {
    for (std::string& entry : events) {
        AnalyzeEventStr(entry);
    }
}


void EventProcessor::PrintEvent(nlohmann::json j) {
    // Output accordingly
    if (g_Config.hide_full_output) {
        if (event_count >= 100) {
            if (event_count % 100 == 0) {
                std::cout << "O";
            }
        }
        else if (event_count >= 10) {
            if (event_count % 10 == 0) {
                std::cout << "o";
            }
        }
        else {
            std::cout << ".";
        }
    }
    else {
        std::cout << j.dump() << "\n";
    }
}


void EventProcessor::EventStats(nlohmann::json& j) {
    if (j["type"] == "kernel") {
        num_kernel += 1;
    }
    else if (j["type"] == "dll") {
        num_dll += 1;
    }
    else if (j["type"] == "etw") {
        if (j["provider_name"] == "Microsoft-Windows-Threat-Intelligence") {
            num_etwti += 1;
        }
        else {
            num_etw += 1;
        }
    }
}


void EventProcessor::ResetData() {
    init();
}


void EventProcessor::GenerateNewTraceId() {
    trace_id = rand();
}


std::string EventProcessor::GetAllAsJson() {
    return nlohmann::json(json_entries).dump();
}


void EventProcessor::SaveToFile() {
    try {
        std::string data = GetAllAsJson();
        std::string filename = "C:\\RedEdr\\Data\\" + get_time_for_file() + ".events.json";
        write_file(filename, data);
        LOG_A(LOG_INFO, "EventProcessor: Saved events to %s", filename.c_str());
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "EventProcessor: Error saving events to file: %s", e.what());
    }
}


// Module functions
HANDLE EventProcessor_thread;


// Thread which retrieves and processes events from EventAggregator
DWORD WINAPI EventProcessorThread(LPVOID param) {
    try {
        size_t arrlen = 0;
        std::unique_lock<std::mutex> lock(g_EventAggregator.analyzer_shutdown_mtx);

        while (true) {
            // Block for new events
            g_EventAggregator.cv.wait(lock, [] { return g_EventAggregator.HasMoreEvents() || g_EventAggregator.done; });
            if (g_EventAggregator.done) {
                break;
            }
            // get em events
            std::vector<std::string> new_entries = g_EventAggregator.GetEvents();

            // process
            g_EventProcessor.AnalyzeNewEvents(new_entries);
        }
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "EventProcessorThread: Exception in main loop: %s", e.what());
    }
    catch (...) {
        LOG_A(LOG_ERROR, "EventProcessorThread: Unknown exception in main loop");
    }

    LOG_A(LOG_INFO, "!EventProcessor: Thread finished");
    return 0;
}


int InitializeEventProcessor(std::vector<HANDLE>& threads) {
    EventProcessor_thread = CreateThread(NULL, 0, EventProcessorThread, NULL, 0, NULL);
    if (EventProcessor_thread == NULL) {
        LOG_A(LOG_ERROR, "EventProcessor: Failed to create thread for EventProcessor");
        return 1;
    }
    LOG_A(LOG_INFO, "!EventProcessor: Started Thread (handle %p)", EventProcessor_thread);

    threads.push_back(EventProcessor_thread);
    return 0;
}


void StopEventProcessor() {
    if (EventProcessor_thread != NULL) {
        g_EventAggregator.Stop();
    }
}

