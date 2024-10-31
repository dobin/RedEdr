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



DWORD WINAPI WebserverThread(LPVOID param) {
    LOG_A(LOG_INFO, "!WEB: Start Webserver thread");
    
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        std::string indexhtml = read_file("index.html");
        res.set_content(indexhtml, "text/html");
    });

    svr.Get("/api/events", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(g_EventProducer.GetAllAsJson(), "application/json; charset=UTF-8");
    });

    svr.Get("/api/detections", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(GetAllDetectionsAsJson(), "application/json; charset=UTF-8");
    });

    svr.Get("/api/stats", [](const httplib::Request&, httplib::Response& res) {
        size_t event_count = g_EventProducer.GetEventCount();
        int last_print = g_EventProducer.GetLastPrintIndex();

        std::stringstream ss;
        ss << "Event Count:" << event_count << "<br>";
        ss << "Last Print :" << last_print + 1; // +1 so it looks nicer
        std::string stats = ss.str();
        res.set_content(stats, "application/json; charset=UTF-8");
    });


    svr.Get("/api/reset", [](const httplib::Request&, httplib::Response& res) {
        LOG_A(LOG_INFO, "Reset stats");
        g_EventProducer.ResetData();
        AResetData();
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

