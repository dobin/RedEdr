#include <iostream>
#include <sstream>
#include <vector>

#include "event_aggregator.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"


/* Retrieves events from all subsystems (ETW, ETWTI, Kernel, DLL)
   as JSON text. Buffer it here until Analyzer collects em.

   It mostly makes sure all events are collected as fast
   as possible, with as little processing as possible.
*/

// Global
EventAggregator g_EventAggregator;


void EventAggregator::NewEvent(std::string eventStr) {
    // Add to cache
    output_mutex.lock();
    output_entries.push_back(eventStr);
    output_count++;
    
    // Debug: Record events
    // This needs to be in the mutex, or the \r\n may not be written correctly
    if (recorder_file != NULL) {
        fprintf(recorder_file, eventStr.c_str());
        fprintf(recorder_file, "\r\n");
    }
    
    output_mutex.unlock();

    // Notify the analyzer thread
    cv.notify_one();
}


void EventAggregator::do_output(std::wstring eventWstr) {
    try {
        // Add to cache
        std::string json = wstring2string(eventWstr);
        output_mutex.lock();
        output_entries.push_back(json);
        output_count++;

        // Debug: Record events
        // This needs to be in the mutex, or the \r\n may not be written correctly
        if (recorder_file != NULL) {
            fprintf(recorder_file, json.c_str());
            fprintf(recorder_file, "\r\n");
        }

        output_mutex.unlock();

        // Notify the analyzer thread
        cv.notify_one();
    }
    catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "EventAggregator::do_output: String conversion failed: %s", e.what());
    }
}


std::vector<std::string> EventAggregator::GetEvents() {
    std::vector<std::string> newEvents;

    output_mutex.lock();
    newEvents = output_entries; // Deep Copy!
    output_entries.clear();
    output_mutex.unlock();

    return newEvents;
}


BOOL EventAggregator::HasMoreEvents() {
    // Lock for now
    std::lock_guard<std::mutex> lock(output_mutex);

    if (output_entries.size() > 0) {
        return TRUE;
    }
    else {
        return FALSE;
    }
}


void EventAggregator::Stop() {
    done = TRUE;
    cv.notify_all();
}


void EventAggregator::ResetData() {
    output_mutex.lock();
    output_entries.clear();
    output_count = 0;  // Reset count as well
    output_mutex.unlock();
}


unsigned int EventAggregator::GetCount() {
    std::lock_guard<std::mutex> lock(output_mutex);
    return output_count;
}


void EventAggregator::InitRecorder(std::string filename) {
    LOG_A(LOG_INFO, "EventAggregator: Recording all events into %s", filename.c_str());
    errno_t err = fopen_s(&recorder_file, filename.c_str(), "w");
    if (err != 0 || !recorder_file) {
        LOG_A(LOG_ERROR, "EventAggregator: Could not open %s for writing", filename.c_str());
    }
}

void EventAggregator::StopRecorder() {
    std::lock_guard<std::mutex> lock(output_mutex);
    if (recorder_file != NULL) {
        fclose(recorder_file);
        recorder_file = NULL;
        LOG_A(LOG_INFO, "EventAggregator: Stopped recording");
    }
}
