#include <iostream>
#include <filesystem>
#include <vector>

#include "httplib.h" // Needs to be on top?

#include "event_aggregator.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"
#include "webserver.h"
#include "process_resolver.h"
#include "manager.h"
#include "event_detector.h"
#include "event_processor.h"

using json = nlohmann::json;


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
    std::vector<std::wstring> names = GetFilesInDirectory(L"C:\\RedEdr\\Data\\*.events.json");
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
        std::string indexhtml = read_file("C:\\RedEdr\\index.html");
        res.set_content(indexhtml, "text/html");
    });
    svr.Get("/recordings", [](const httplib::Request&, httplib::Response& res) {
        std::string indexhtml = read_file("C:\\RedEdr\\recording.html");
        res.set_content(indexhtml, "text/html");
    });
    svr.Get("/static/design.css", [](const httplib::Request&, httplib::Response& res) {
        std::string indexhtml = read_file("C:\\RedEdr\\design.css");
        res.set_content(indexhtml, "text/css");
    });
    svr.Get("/static/shared.js", [](const httplib::Request&, httplib::Response& res) {
        std::string indexhtml = read_file("C:\\RedEdr\\shared.js");
        res.set_content(indexhtml, "text/javascript");
    });

    svr.Get("/api/events", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(g_EventProcessor.GetAllAsJson(), "application/json; charset=UTF-8");
    });

    svr.Get("/api/detections", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(g_EventDetector.GetAllDetectionsAsJson(), "application/json; charset=UTF-8");
    });

    svr.Get("/api/recordings", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(getRecordingsAsJson(), "application/json; charset=UTF-8");
    });
    svr.Get("/api/recordings/:id", [](const httplib::Request& req, httplib::Response& res) {
        auto user_id = req.path_params.at("id");
        std::string path = "C:\\RedEdr\\Data\\" + user_id + ".events.json";
        std::string data = read_file(path);
        res.set_content(data.c_str(), "application/json");
    });

    svr.Get("/api/stats", [](const httplib::Request&, httplib::Response& res) {
        nlohmann::json stats = {
            {"events_count", g_EventAggregator.GetCount()},
            {"detections_count", g_EventDetector.GetDetectionsCount()},
            {"num_kernel", g_EventProcessor.num_kernel},
            {"num_etw", g_EventProcessor.num_etw},
            {"num_etwti", g_EventProcessor.num_etwti},
            {"num_dll", g_EventProcessor.num_dll},
            {"num_process_cache", g_ProcessResolver.GetCacheCount()}
        };
        res.set_content(stats.dump(), "application/json; charset=UTF-8");
    });
    svr.Get("/api/meminfo", [](const httplib::Request&, httplib::Response& res) {
        nlohmann::json info = g_EventDetector.GetTargetMemoryChanges()->ToJson();
        res.set_content(info.dump(), "application/json; charset=UTF-8");
    });

    svr.Get("/api/trace", [](const httplib::Request& req, httplib::Response& res) {
        json response = { {"trace", wcharToString(g_config.targetExeName) }};
        res.set_content(response.dump(), "application/json");
    });
    svr.Post("/api/trace", [](const httplib::Request& req, httplib::Response& res) {
        try {
            auto data = json::parse(req.body);
            if (data.contains("trace")) {
                std::string traceName = data["trace"].get<std::string>();
				LOG_A(LOG_INFO, "Trace target: %s", traceName.c_str());
				g_config.targetExeName = stringToWChar(traceName.c_str());
                json response = { {"result", "ok"} };
                res.set_content(response.dump(), "application/json");
            }
            else {
                json error = { {"error", "No 'trace' key provided"} };
                res.status = 400;
                res.set_content(error.dump(), "application/json");
            }
        }
        catch (const json::parse_error& e) {
            json error = { {"error", "Invalid JSON data: " + std::string(e.what())}};
            res.status = 400;
            res.set_content(error.dump(), "application/json");
        }
    });
    svr.Get("/api/save", [](const httplib::Request&, httplib::Response& res) {
        g_EventProcessor.SaveToFile();
    });
    svr.Get("/api/reset", [](const httplib::Request&, httplib::Response& res) {
        ResetEverything();
    });
    svr.Get("/api/start", [](const httplib::Request& req, httplib::Response& res) {
        g_config.enabled = TRUE;
        ManagerReload();
        json response = { {"status", "ok"}};
        res.set_content(response.dump(), "application/json");
    });
    svr.Get("/api/stop", [](const httplib::Request& req, httplib::Response& res) {
        g_config.enabled = FALSE;
        ManagerReload();
        json response = { {"status", "ok"} };
        res.set_content(response.dump(), "application/json");
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

