#include <iostream>
#include <sstream>
#include <vector>

#include "processinfo.h"
#include "event_processor.h"
#include "event_aggregator.h"
#include "event_augmenter.h"
#include "event_detector.h"
#include "processcache.h"

#include "utils.h"
#include "config.h"


/* Gets new events from EventAggregator and processes them:
 * - Keeps stats
 * - Keeps copy of all events
 * - Augments events with additional information
 * - Perform the detections
 * - Query process for more information
 * 
 */

EventProcessor g_EventProcessor;


EventProcessor::EventProcessor() {
    GenerateNewTraceId();
}


void EventProcessor::PrintEvent(nlohmann::json j) {
    // Output accordingly
    if (g_config.hide_full_output) {
        if (event_count >= 100) {
            if (event_count % 100 == 0) {
                std::wcout << L"O";
            }
        }
        else if (event_count >= 10) {
            if (event_count % 10 == 0) {
                std::wcout << L"o";
            }
        }
        else {
            std::wcout << L".";
        }
    }
    else {
        std::cout << j.dump() << "\n";
    }
}


void EventProcessor::AnalyzeEventJson(nlohmann::json& j) {
    j["id"] = json_entries.size();
    j["trace_id"] = trace_id;

    // Sanity check
    if (!j.contains("type")) {
        LOG_A(LOG_WARNING, "No type? %s", j.dump().c_str());
        return;
    }

    // Stats
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

    // augment process information the first time
    if (!j.contains("pid")) {
        //LOG_A(LOG_WARNING, "No pid? %s", j.dump().c_str());
    }
    else {
        Process* process = g_ProcessCache.getObject(j["pid"].get<DWORD>());
        if (process->augmented == 0) {
            // Augment the process (could take some time)
            AugmentProcess(j["pid"].get<DWORD>(), process);
            
            // Print some of the gathered information
            std::wstring o = format_wstring(L"{\"type\":\"peb\",\"time\":%lld,\"id\":%lld,\"parent_pid\":%lld,\"image_path\":\"%s\",\"commandline\":\"%s\",\"working_dir\":\"%s\",\"is_debugged\":%d,\"is_protected_process\":%d,\"is_protected_process_light\":%d,\"image_base\":%llu}",
                get_time(),
                process->id,
                process->parent_pid,
                JsonEscape2(process->image_path.c_str()).c_str(),
                JsonEscape2(process->commandline.c_str()).c_str(),
                JsonEscape2(process->working_dir.c_str()).c_str(),
                process->is_debugged,
                process->is_protected_process,
                process->is_protected_process_light,
                process->image_base
            );

            process->augmented++;
            g_EventAggregator.do_output(o);
        }
    }

    // additional checks based on counted events
    if (json_entries.size() == 32) {
        if (j.contains("pid")) {
            DWORD pid = j["pid"].get<DWORD>();
            //QueryProcessInfo(pid, NULL);
        }
    }

    // Augment with memory info
    AugmentAddresses(j);

    // Track Memory changes
    ScanForMemoryChanges(j);
    //targetMemoryChanges.PrintMemoryRegions();

    // Perform Detections
    ScanForDetections(j);

    // Print it
    PrintEvent(j);

    // Has to be at the end as we dont store reference
    json_entries.push_back(j);
    event_count++;

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


void EventProcessor::ResetData() {
    GenerateNewTraceId();
    //detections.clear();
    json_entries.clear();
}


void EventProcessor::GenerateNewTraceId() {
    trace_id = rand();
}


std::string EventProcessor::GetAllAsJson() {
    return nlohmann::json(json_entries).dump();
}


void EventProcessor::SaveToFile() {
    std::string data = GetAllAsJson();
    std::string filename = "C:\\RedEdr\\Data\\" + get_time_for_file() + ".events.json";
    write_file(filename, data);
}


// Module functions

HANDLE EventProcessor_thread;


DWORD WINAPI EventProcessorThread(LPVOID param) {
    LOG_A(LOG_INFO, "!EventProcessor: Start thread");
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
        g_EventProcessor.AnalyzeNewEvents(new_entries);
    }

    LOG_A(LOG_INFO, "!EventProcessor: Exit thread");
    return 0;
}


int InitializeEventProcessor(std::vector<HANDLE>& threads) {
    EventProcessor_thread = CreateThread(NULL, 0, EventProcessorThread, NULL, 0, NULL);
    if (EventProcessor_thread == NULL) {
        LOG_A(LOG_ERROR, "WEB: Failed to create thread for EventProcessor");
        return 1;
    }
    threads.push_back(EventProcessor_thread);
    return 0;
}


void StopEventProcessor() {
    if (EventProcessor_thread != NULL) {
        g_EventAggregator.Stop();
    }
}

