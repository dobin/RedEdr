#include <iostream>
#include <filesystem>
#include <vector>

#include "httplib.h" // Needs to be on top?

#include "eventproducer.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"
#include "webserver.h"
#include "processcache.h"
#include "analyzer.h"

HANDLE webserver_thread;
httplib::Server svr;


std::wstring StripToFirstDot(const std::wstring& input) {
    size_t dot_position = input.find(L'.');
    if (dot_position != std::wstring::npos) {
        return input.substr(0, dot_position);
    }
    return input;
}

std::vector<std::wstring> GetFilesInDirectory(const std::wstring& directory) {
    std::vector<std::wstring> files;
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = FindFirstFile(directory.c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to open directory: " << directory << std::endl;
        return files;
    }

    do {
        const std::wstring fileOrDir = findFileData.cFileName;
        if (fileOrDir != L"." && fileOrDir != L"..") {
            files.push_back(StripToFirstDot(fileOrDir));
        }
    } while (FindNextFile(hFind, &findFileData) != 0);

    FindClose(hFind);
    return files;
}

std::string getRecordingsAsJson() {
    std::stringstream output;
    output << "[";
    //std::vector<std::wstring> names = GetFilesInDirectory(L"C:\\RedEdr\\Data\\*.events.json");
    std::vector<std::wstring> names = GetFilesInDirectory(L"Data\\*.events.json");
    for (auto it = names.begin(); it != names.end(); ++it) {
        output << "\"" << wstring_to_utf8(*it) << "\"";
        if (std::next(it) != names.end()) {
            output << ",";  // Add comma only if it's not the last element
        }
    }
    output << "]";
    return output.str();
}

DWORD WINAPI WebserverThread(LPVOID param) {
    LOG_A(LOG_INFO, "!WEB: Start Webserver thread");
    
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        std::string indexhtml = read_file("index.html");
        res.set_content(indexhtml, "text/html");
    });
    svr.Get("/recordings", [](const httplib::Request&, httplib::Response& res) {
        std::string indexhtml = read_file("recording.html");
        res.set_content(indexhtml, "text/html");
    });
    svr.Get("/static/design.css", [](const httplib::Request&, httplib::Response& res) {
        std::string indexhtml = read_file("design.css");
        res.set_content(indexhtml, "text/css");
    });
    svr.Get("/static/shared.js", [](const httplib::Request&, httplib::Response& res) {
        std::string indexhtml = read_file("shared.js");
        res.set_content(indexhtml, "text/javascript");
    });

    svr.Get("/api/events", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(g_EventProducer.GetAllAsJson(), "application/json; charset=UTF-8");
    });

    svr.Get("/api/detections", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(g_Analyzer.GetAllDetectionsAsJson(), "application/json; charset=UTF-8");
    });

    svr.Get("/api/recordings", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(getRecordingsAsJson(), "application/json; charset=UTF-8");
    });
    svr.Get("/api/recordings/:id", [](const httplib::Request& req, httplib::Response& res) {
        auto user_id = req.path_params.at("id");
        std::string path = "Data\\" + user_id + ".events.json";
        std::cout << path;
        std::string data = read_file(path);
        res.set_content(data.c_str(), "application/json");
    });

    svr.Get("/api/stats", [](const httplib::Request&, httplib::Response& res) {
        size_t event_count = g_EventProducer.GetEventCount();
        int last_print = g_EventProducer.GetLastPrintIndex();

        std::stringstream ss;
        ss << "{ \"events_count\":" << event_count << ",";
        ss << "\"detections_count\":" << (last_print + 1) << "}"; // +1 so it looks nicer
        std::string stats = ss.str();
        res.set_content(stats, "application/json; charset=UTF-8");
    });


    svr.Get("/api/reset", [](const httplib::Request&, httplib::Response& res) {
        LOG_A(LOG_INFO, "Reset stats");
        g_EventProducer.ResetData();
        g_Analyzer.ResetData();
        g_ProcessCache.removeAll();
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

