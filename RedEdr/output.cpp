#include "httplib.h" // Needs to be on top?

#include <iostream>
#include <sstream>
#include <vector>

#include <locale>
#include <codecvt>

#include "output.h"
#include "event_producer.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"


// Analyzer
HANDLE analyzer_thread;

// Web
HANDLE webserver_thread;
httplib::Server svr;


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

// cant be function variable?
int last = -1; // needs to be -1 so element 0 will be returned


DWORD WINAPI AnalyzerThread(LPVOID param) {
    LOG_A(LOG_INFO, "!Analyzer: Start thread");
    size_t arrlen = 0;
    std::unique_lock<std::mutex> lock(g_EventProducer.analyzer_shutdown_mtx);

    while (true) {
        // Block for new events
        g_EventProducer.cv.wait(lock, [] { return g_EventProducer.HasMoreEvents(last) || g_EventProducer.done; });  

        // get em events
        std::vector<std::string> output_entries = g_EventProducer.GetEventsFrom(last);

        // handle em
        arrlen = output_entries.size();
        for (std::string& entry : output_entries) {
            AnalyzeEvent(entry);
        }
        last += arrlen;
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
        res.set_content(g_EventProducer.GetAllAsJson(), "application/json; charset=UTF-8");
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