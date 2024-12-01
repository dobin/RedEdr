#include "httplib.h" // Needs to be on top?

#include <iostream>
#include <sstream>
#include <vector>

#include <locale>
#include <codecvt>

#include "eventproducer.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"


/* Retrieves events from all subsystems:
     - ETW
     - ETWTI
     - Kernel
     - DLL
    as "text", convert to json-text, and buffer em. 

    It mostly makes sure all events are collected as fast
    as possible, with as little processing as possible.

    Analyzer will collect the events regularly.
*/

// Global
EventProducer g_EventProducer;


void EventProducer::do_output(std::wstring eventWstr) {
    // Convert to json and add it to the list
    std::string json = ConvertLogLineToJsonEvent(eventWstr);
    output_mutex.lock();
    output_entries.push_back(json);
    output_mutex.unlock();
    output_count++;

    // print it
    if (g_config.hide_full_output) {
        if (output_count >= 100) {
            if (output_count % 100 == 0) {
                std::wcout << L"O";
            }
        }
        else if (output_count >= 10) {
            if (output_count % 10 == 0) {
                std::wcout << L"o";
            }
        }
        else {
            std::wcout << L".";
        }
    }
    else {
        std::wcout << eventWstr << L"\n";
    }

    // Notify the analyzer thread
    cv.notify_one();
}


std::vector<std::string> EventProducer::GetEvents() {
    std::vector<std::string> newEvents;

    output_mutex.lock();
    newEvents = output_entries;
    output_entries.clear();
    output_mutex.unlock();

    return newEvents;
}


// Function to parse the input and convert it into UTF8 JSON
std::string EventProducer::ConvertLogLineToJsonEvent(std::wstring input) {
    std::wstring result;
    result += L"{\"";

    for (size_t i = 0; i < input.size(); ++i) {
        wchar_t ch = input[i];
        wchar_t n = (i < input.size() - 1) ? input[i + 1] : L' ';
        wchar_t p = (i > 0) ? input[i - 1] : L' ';

        if (ch == L';' && i == input.size() - 1) {
            continue; // break basically, dont add
        }

        if (ch == L'"') {
            continue; // skip
        }
        else if (ch == L':') {
            if ((p == L'C' || p == L'c') && n == L'\\') { // skip "C:\" 
                result += ch;
                continue;
            }

            if (n == L'[') {
                result += L"\""; // Add closing quote 
                result += ch;
            }
            else {
                result += L"\""; // Add opening quote 
                result += ch;
                result += L"\""; // Add closing quote 
            }
        }
        else if (ch == L';') {
            result += L"\""; // Add opening quote 
            result += L',';
            result += L"\""; // Add closing quote 
        }
        else if (ch == L'{') {
            result += ch;
            result += L"\""; // Add opening quote
        }
        else if (ch == L'}') {
            result += L"\""; // Add closing quote
            result += ch;
        }
        else if (ch == L',' && n == L']') {
            // ignore trailing ,]
        }
        else if (ch == L'\\') { // escape backslash
            //result += ch + ch;  // Fail, would be interesting to know why
            result += L"\\\\";
        }
        else {
            // Copy the character as-is
            result += ch;
        }
    }

    // FUUUU
    if (result[result.size() - 1] == ']') {
        result += L"}";
    }
    else {
        result += L"\"}";
    }

    std::string eventStrUtf8 = wstring_to_utf8(result);
    return eventStrUtf8;
}


BOOL EventProducer::HasMoreEvents() {
    // Lock for now
    std::lock_guard<std::mutex> lock(output_mutex);

    if (output_entries.size() > 0) {
        return TRUE;
    }
    else {
        return false;
    }
}


void EventProducer::Stop() {
    done = TRUE;
    g_EventProducer.cv.notify_all();
}


void EventProducer::ResetData() {
    output_mutex.lock();
    output_entries.clear();
    output_mutex.unlock();
}


unsigned int EventProducer::GetCount() {
    return output_count;
}
