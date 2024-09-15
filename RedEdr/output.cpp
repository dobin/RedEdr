#include "httplib.h" // Needs to be on top?

#include <iostream>
#include <sstream>
#include <vector>

#include <locale>
#include <codecvt>

#include "loguru.hpp"


std::vector<std::wstring> output_entries;
std::mutex output_mutex;

HANDLE webserver_thread;
httplib::Server svr;


std::wstring ConvertToJSON(const std::wstring& input)
{
    std::vector<std::pair<std::wstring, std::wstring>> keyValuePairs;
    std::wstringstream wss(input);
    std::wstring token;

    // Split by ';'
    while (std::getline(wss, token, L';'))
    {
        std::wstringstream kvStream(token);
        std::wstring key, value;

        // Split by ':'
        if (std::getline(kvStream, key, L':') && std::getline(kvStream, value))
        {
            keyValuePairs.emplace_back(key, value);
        }
    }

    // Construct JSON
    std::wstringstream jsonStream;
    jsonStream << L"{";

    bool first = true;
    for (const auto& pair : keyValuePairs)
    {
        if (!first)
        {
            jsonStream << L", ";
        }
        jsonStream << L"\"" << pair.first << L"\": \"" << pair.second << L"\"";
        first = false;
    }

    jsonStream << L"}";

    return jsonStream.str();
}


void do_output(std::wstring str) {
    // Convert to json and add it to the global list
    std::wstring json = ConvertToJSON(str);
    output_mutex.lock();
    output_entries.push_back(json);
    output_mutex.unlock();
    
    // print it
    //std::wcout << str << L"\n";
    std::wcout << L".";
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
        start_pos += to.length(); // Move past the last replaced occurrence
    }
    return result;
}

std::string output_as_json() {
    std::wstringstream output;
    int otype = 0;

    output_mutex.lock();

    if (otype == 0) { // elastic style one entry per line
        for (auto it = output_entries.begin(); it != output_entries.end(); ++it) {
            output << replace_all(*it, L"\\", L"\\\\") << std::endl;
        }
    }
    else if (otype == 1) { // 1 line json
        output << "[";
        for (auto it = output_entries.begin(); it != output_entries.end(); ++it) {
            output << replace_all(*it, L"\\", L"\\\\");
            if (std::next(it) != output_entries.end()) {
                output << ", ";  // Add comma only if it's not the last element
            }
        }
        output << "]";
    }
    
    output_mutex.unlock();

    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(output.str());
}

DWORD WINAPI WebserverThread(LPVOID param) {
    LOG_F(INFO, "!WEB: Start Webserver thread");
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(output_as_json(), "application/json; charset=UTF-8");
        });
    LOG_F(INFO, "WEB: Web Server listening on http://localhost:8080");
    svr.listen("localhost", 8080);
    LOG_F(INFO, "!WEB: Exit Webserver thread");
    
    return 0;
}


int InitializeWebServer(std::vector<HANDLE>& threads) {
    webserver_thread = CreateThread(NULL, 0, WebserverThread, NULL, 0, NULL);
    if (webserver_thread == NULL) {
        LOG_F(ERROR, "WEB: Failed to create thread for webserver");
        return 1;
    }
    threads.push_back(webserver_thread);
    return 0;
}

void StopWebServer() {
    if (webserver_thread != NULL) {
        svr.stop();
        //TerminateThread(webserver_thread, 0);
    }
}