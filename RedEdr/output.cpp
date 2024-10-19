#include "httplib.h" // Needs to be on top?

#include <iostream>
#include <sstream>
#include <vector>

#include <locale>
#include <codecvt>

#include "config.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"


// JSON should be UTF-8 which is std::string...
std::vector<std::string> output_entries;
std::mutex output_mutex;
unsigned int output_count = 0;

// Analyzer
HANDLE analyzer_thread;
std::condition_variable cv;
size_t read_index = 0;  // Index to track the last read entry
bool done = false;  // Flag to signal when to stop the consumer thread
std::mutex analyzer_shutdown_mtx;

// Web
HANDLE webserver_thread;
httplib::Server svr;


// Function to parse the input and convert it into UTF8 JSON
std::string ConvertLineToJson(const std::wstring& input) {
    std::wstring result;
    result += L"{\"";

    for (size_t i = 0; i < input.size(); ++i) {
        wchar_t ch = input[i];
        wchar_t n = (i<input.size() - 1) ? input[i + 1] : L' ';
        wchar_t p = (i > 0) ? input[i - 1] : L' ';
        
        if (ch == L';' && i == input.size() - 1) {
            continue; // break basically, dont add
        }

        if (ch == L'"') {
            continue; // skip
        } else if (ch == L':') {
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
        } else if (ch == L';') {
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


void do_output(std::wstring eventWstr) {
    // Convert to json and add it to the global list
    std::string json = ConvertLineToJson(eventWstr);
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


void print_all_output() {
    std::cout << "[" << std::endl;
    output_mutex.lock();
    for (const auto& str : output_entries) {
        std::cout << str << ", " << std::endl;
    }
    output_mutex.unlock();
    std::cout << "]" << std::endl;
}


std::string GetJsonFromEntries() {
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


/*** Analyzer ***/

void AnalyzeEvent(std::string eventStr) {
    //std::cout << L"Processing: " << eventStr << std::endl;
    LOG_A(LOG_INFO, "Proc: %s", eventStr.c_str());

    try
    {
        nlohmann::json j = nlohmann::json::parse(eventStr);
    }
    catch (const nlohmann::json::exception& e)
    {
        LOG_A(LOG_WARNING, "JSON Parser Exception msg: %s", e.what());
        LOG_A(LOG_WARNING, "JSON Parser Exception event: %s", eventStr.c_str());
        return;
    }


    // Parse event

    

}


DWORD WINAPI AnalyzerThread(LPVOID param) {
    LOG_A(LOG_INFO, "!Analyzer: Start thread");
    size_t arrlen = 0;

    while (true) {
        std::unique_lock<std::mutex> lock(analyzer_shutdown_mtx);
        cv.wait(lock, [] { return read_index < output_entries.size() || done; });  // Wait for new data or termination signal

        output_mutex.lock();
        arrlen = output_entries.size();
        output_mutex.unlock();

        // If done and no more entries to read, break the loop
        if (done && read_index >= arrlen) {
            break;
        }

        // Process all new entries from the current read_index
        while (read_index < arrlen) {
            output_mutex.lock();
            std::string entry = output_entries[read_index];
            output_mutex.unlock();
            AnalyzeEvent(entry);
            ++read_index;  // Move to the next unread entry
        }
    }

    LOG_A(LOG_INFO, "!Analyzer: Exit thread");
    return 0;
}


int InitializeAnalyzer(std::vector<HANDLE>& threads) {
    analyzer_thread = CreateThread(NULL, 0, AnalyzerThread, NULL, 0, NULL);
    if (analyzer_thread == NULL) {
        LOG_A(LOG_ERROR, "WEB: Failed to create thread for webserver");
        return 1;
    }
    threads.push_back(analyzer_thread);
    return 0;
}


void StopAnalyzer() {
    if (analyzer_thread != NULL) {
    }
}


/*** Web ***/

DWORD WINAPI WebserverThread(LPVOID param) {
    LOG_A(LOG_INFO, "!WEB: Start Webserver thread");
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(GetJsonFromEntries(), "application/json; charset=UTF-8");
        });
    LOG_A(LOG_INFO, "WEB: Web Server listening on http://localhost:8080");
    svr.listen("localhost", 8080);
    LOG_A(LOG_INFO, "!WEB: Exit Webserver thread");
    
    return 0;
}


int InitializeWebServer(std::vector<HANDLE>& threads) {
    webserver_thread = CreateThread(NULL, 0, WebserverThread, NULL, 0, NULL);
    if (webserver_thread == NULL) {
        LOG_A(LOG_ERROR, "WEB: Failed to create thread for webserver");
        return 1;
    }
    threads.push_back(webserver_thread);
    return 0;
}


void StopWebServer() {
    if (webserver_thread != NULL) {
        svr.stop();
    }
}