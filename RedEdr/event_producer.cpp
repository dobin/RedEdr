#include "httplib.h" // Needs to be on top?

#include <iostream>
#include <sstream>
#include <vector>

#include <locale>
#include <codecvt>

#include "event_producer.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"


// Create us
EventProducer g_EventProducer;


// Function to parse the input and convert it into UTF8 JSON
std::string EventProducer::ConvertLogLineToJsonEvent(const std::wstring& input) {
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
            result += ch + ch;
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


void EventProducer::do_output(std::wstring eventWstr) {
    // Convert to json and add it to the global list
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


BOOL EventProducer::HasMoreEvents() {
    // No lock?
    return (last < static_cast<int>(output_entries.size()) - 1);
}


void EventProducer::ResetData() {
    last = -1;
    output_entries.clear();
    output_count = 0;
}


size_t EventProducer::GetEventCount() {
    return output_entries.size();
}


int EventProducer::GetLastPrintIndex() {
    return last;
}


// Returns a vector of all new events starting from last (which starts at -1)
std::vector<std::string> EventProducer::GetEventsFrom() {
    std::vector<std::string> newEvents;

    // If the last index is valid and there are more events, return the new ones
    output_mutex.lock();
    if (last >= static_cast<int>(output_entries.size())) {
        return newEvents;
    }
    if (last == -1) {
        // Get all entries
        newEvents.assign(output_entries.begin(), output_entries.end());
    }
    else {
        // Get new entries
        newEvents.assign(output_entries.begin() + last + 1, output_entries.end());
    }
    output_mutex.unlock();

    last += newEvents.size();

    return newEvents;
}


void EventProducer::PrintAll() {
    std::cout << "[" << std::endl;
    output_mutex.lock();
    for (const auto& str : output_entries) {
        std::cout << str << ", " << std::endl;
    }
    output_mutex.unlock();
    std::cout << "]" << std::endl;
}


std::string EventProducer::GetAllAsJson() {
    std::stringstream output;
    output << "[";

    output_mutex.lock();
    for (auto it = output_entries.begin(); it != output_entries.end(); ++it) {
        output << ReplaceAllA(*it, "\\", "\\\\");
        if (std::next(it) != output_entries.end()) {
            output << ",";  // Add comma only if it's not the last element
        }
    }
    output_mutex.unlock();

    output << "]";
    return output.str();
}
