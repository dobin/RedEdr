#include "httplib.h" // Needs to be on top?

#include <iostream>
#include <sstream>
#include <vector>

#include <locale>
#include <codecvt>

#include "config.h"
#include "logging.h"


std::vector<std::wstring> output_entries;
std::mutex output_mutex;
unsigned int output_count = 0;

HANDLE webserver_thread;
httplib::Server svr;


// Function to parse the input and convert it into JSON
std::wstring ConvertLineToJson(const std::wstring& input) {
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
        else {
            // Copy the character as-is
            result += ch;
        }
    }

    // FUUUU
    if (result[result.size() - 1] == L']') {
        result += L"}";
    }
    else {
        result += L"\"}";
    }
    
    return result;
}


void do_output(std::wstring str) {
    // Convert to json and add it to the global list
    std::wstring json = ConvertLineToJson(str);
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
        std::wcout << str << L"\n";
    }
}


void print_all_output() {
    std::wcout << "[" << std::endl;
    output_mutex.lock();
    for (const auto& str : output_entries) {
        std::wcout << str << ", " << std::endl;
    }
    output_mutex.unlock();
    std::wcout << "]" << std::endl;
}


std::wstring replace_all(const std::wstring& str, const std::wstring& from, const std::wstring& to) {
    std::wstring result = str;
    if (from.empty()) return result;
    size_t start_pos = 0;
    while ((start_pos = result.find(from, start_pos)) != std::wstring::npos) {
        result.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return result;
}


std::string GetJsonFromEntries() {
    std::wstringstream output;
    int otype = 1;

    output_mutex.lock();

    if (otype == 0) { // elastic style one entry per line
        for (auto it = output_entries.begin(); it != output_entries.end(); ++it) {
            output << replace_all(*it, L"\\", L"\\\\") << std::endl;
        }
    }
    else if (otype == 1) { // 1 line json array
        output << "[";
        for (auto it = output_entries.begin(); it != output_entries.end(); ++it) {
            output << replace_all(*it, L"\\", L"\\\\");
            if (std::next(it) != output_entries.end()) {
                output << ",";  // Add comma only if it's not the last element
            }
        }
        output << "]";
    }
    
    output_mutex.unlock();

    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(output.str());
}


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