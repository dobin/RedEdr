#include "httplib.h" // Needs to be on top?

#include "event_producer.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"
#include "webserver.h"

HANDLE webserver_thread;
httplib::Server svr;


std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Could not open file: " << path << std::endl;
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf(); // Read the file into the stringstream
    return buffer.str();
}



DWORD WINAPI WebserverThread(LPVOID param) {
    LOG_A(LOG_INFO, "!WEB: Start Webserver thread");
    
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        std::string indexhtml = read_file("index.html");
        res.set_content(indexhtml, "text/html");
    });

    svr.Get("/api/events", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(g_EventProducer.GetAllAsJson(), "application/json; charset=UTF-8");
    });

    svr.Get("/api/stats", [](const httplib::Request&, httplib::Response& res) {
        std::string stats = "{ \"bla\": 1, \"gna\": 2 }";
        res.set_content(stats, "application/json; charset=UTF-8");
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

