#include <iostream>
#include <filesystem>
#include <vector>
#include <tchar.h>
#include <windows.h>
#include <wtsapi32.h>
#include <UserEnv.h>
#include <mutex>

#include "httplib.h" // Needs to be on top?

#include "event_aggregator.h"
#include "config.h"
#include "logging.h"
#include "utils.h"
#include "json.hpp"
#include "webserver.h"
#include "process_resolver.h"
#include "manager.h"
#include "event_processor.h"
#include "executor.h"
#include "edr_reader.h"

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")


/* Webserver.cpp: Webserver with REST api to the whole thing
 *   UI to interact with rededr
 *   REST interface (e.g. for RedEdrUi)
 */


using json = nlohmann::json;


HANDLE webserver_thread;
httplib::Server svr;
int webserver_port;


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
        // Can be empty, ignore
        if (g_Config.debug) {
            LOG_W(LOG_INFO, L"No files found in %s", directory.c_str());
        }
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
    try {
        std::stringstream output;
        output << "[";
        std::vector<std::wstring> names = GetFilesInDirectory(L"C:\\RedEdr\\Data\\*.events.json");
        for (auto it = names.begin(); it != names.end(); ++it) {
            std::wstring name = *it;  // Create a proper lvalue for wstring2string
            output << "\"" << wstring2string(name) << ".events.json" << "\"";
            if (std::next(it) != names.end()) {
                output << ",";  // Add comma only if it's not the last element
            }
        }
        output << "]";
        return output.str();
    } catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "Error in getRecordingsAsJson: %s", e.what());
        return "[]";  // Return empty array on error
    }
}


bool StartWithExplorer(std::string programPath) {
    std::string fullpath = "explorer.exe " + programPath;
    wchar_t* commandLine = string2wcharAlloc(fullpath);

    LOG_W(LOG_INFO, L"Executing malware: %s", commandLine);
    
    // Start the process
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi = { 0 };
    BOOL result = CreateProcessW(NULL, commandLine, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    
    // Clean up allocated memory
    delete[] commandLine;
    
    if (!result) {
        wprintf(L"Failed to start %s with explorer.exe. Error: %d\n", 
            L"process", GetLastError());
        return false;
    }

    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}


BOOL ExecMalware(std::string filename, std::string filedata) {
    std::string filepath = "C:\\RedEdr\\data\\" + filename;
    std::ofstream ofs(filepath, std::ios::binary);
    if (ofs) {
        ofs.write(filedata.data(), filedata.size());
        ofs.close();
    }
    else {
        LOG_A(LOG_ERROR, "Could not write file");
        return FALSE;
    }
    
    // Fix memory leak by storing pointer and cleaning up
    wchar_t* wideFilepath = string2wcharAlloc(filepath.c_str());
    g_EdrReader.Start();
    BOOL result = g_Executor.Start(wideFilepath);
    delete[] wideFilepath;
    
    return result;
}


DWORD WINAPI WebserverThread(LPVOID param) {
    // Static
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        try {
            std::string indexhtml = read_file("C:\\RedEdr\\index.html");
            if (indexhtml.empty()) {
                res.status = 404;
                res.set_content("File not found", "text/plain");
                return;
            }
            res.set_content(indexhtml, "text/html");
        } catch (const std::exception& e) {
            LOG_A(LOG_ERROR, "Error serving index.html: %s", e.what());
            res.status = 500;
            res.set_content("Internal server error", "text/plain");
        }
    });
    svr.Get("/static/design.css", [](const httplib::Request&, httplib::Response& res) {
        try {
            std::string indexhtml = read_file("C:\\RedEdr\\design.css");
            if (indexhtml.empty()) {
                res.status = 404;
                res.set_content("File not found", "text/plain");
                return;
            }
            res.set_content(indexhtml, "text/css");
        } catch (const std::exception& e) {
            LOG_A(LOG_ERROR, "Error serving design.css: %s", e.what());
            res.status = 500;
            res.set_content("Internal server error", "text/plain");
        }
    });
    svr.Get("/static/shared.js", [](const httplib::Request&, httplib::Response& res) {
        try {
            std::string indexhtml = read_file("C:\\RedEdr\\shared.js");
            if (indexhtml.empty()) {
                res.status = 404;
                res.set_content("File not found", "text/plain");
                return;
            }
            res.set_content(indexhtml, "text/javascript");
        } catch (const std::exception& e) {
            LOG_A(LOG_ERROR, "Error serving shared.js: %s", e.what());
            res.status = 500;
            res.set_content("Internal server error", "text/plain");
        }
    });

    // Recordings
    svr.Get("/api/recordings", [](const httplib::Request&, httplib::Response& res) {
        try {
            res.set_content(getRecordingsAsJson(), "application/json; charset=UTF-8");
        } catch (const std::exception& e) {
            LOG_A(LOG_ERROR, "Error getting recordings: %s", e.what());
            res.status = 500;
            res.set_content("{\"error\":\"Internal server error\"}", "application/json");
        }
    });
    svr.Get("/api/recordings/:id", [](const httplib::Request& req, httplib::Response& res) {
        auto filename = req.path_params.at("id");
        
        // Validate the ID to prevent path traversal attacks
        if (filename.find("..") != std::string::npos || 
            filename.find("/") != std::string::npos || 
            filename.find("\\") != std::string::npos ||
            filename.empty()) {
            res.status = 400;
            res.set_content("{\"error\": \"Invalid ID\"}", "application/json");
            return;
        }
        
        std::string path = "C:\\RedEdr\\Data\\" + filename;
        std::string data = read_file(path);
        if (data.empty()) {
            res.status = 404;
            res.set_content("{\"error\": \"File not found\"}", "application/json");
            return;
        }
        res.set_content(data.c_str(), "application/json");
    });

    // UI
    svr.Get("/api/stats", [](const httplib::Request&, httplib::Response& res) {
        nlohmann::json stats = {
            {"events_count", g_EventAggregator.GetCount()},
            {"num_kernel", g_EventProcessor.num_kernel},
            {"num_etw", g_EventProcessor.num_etw},
            {"num_etwti", g_EventProcessor.num_etwti},
            {"num_dll", g_EventProcessor.num_dll},
            {"num_process_cache", g_ProcessResolver.GetCacheCount()}
        };
        res.set_content(stats.dump(), "application/json; charset=UTF-8");
    });
    svr.Get("/api/trace", [](const httplib::Request& req, httplib::Response& res) {
        json response = { {"trace", g_Config.targetExeName }};
        res.set_content(response.dump(), "application/json");
    });
    svr.Post("/api/trace", [](const httplib::Request& req, httplib::Response& res) {
        try {
            auto data = json::parse(req.body);
            if (data.contains("trace")) {
                std::string traceName = data["trace"].get<std::string>();
				LOG_A(LOG_INFO, "Trace target: %s", traceName.c_str());
				g_Config.targetExeName = traceName;
                json response = { {"result", "ok"} };
                res.set_content(response.dump(), "application/json");
            }
            else {
                json error_response = { {"error", "No 'trace' key provided"} };
                res.status = 400;
                res.set_content(error_response.dump(), "application/json");
            }
        }
        catch (const json::parse_error& e) {
            json error_response = { {"error", "Invalid JSON data: " + std::string(e.what())}};
            res.status = 400;
            res.set_content(error_response.dump(), "application/json");
        }
    });
    svr.Get("/api/save", [](const httplib::Request&, httplib::Response& res) {
        g_EventProcessor.SaveToFile();
    });
    svr.Get("/api/reset", [](const httplib::Request&, httplib::Response& res) {
        ResetEverything();
    });

    // Logs
    svr.Get("/api/logs/rededr", [](const httplib::Request&, httplib::Response& res) {
        // Arry of Dicts
        // Like:
        /*
            [
                { "date":"2025-07-20-10-36-24",
                  "do_etw":false,
                  "do_etwti":false,
                  "do_hook":false,
                  "do_hook_callstack": true,
                  "func":"init",
                  "target":"otepad",
                  "trace_id":41,
                  "type":"meta",
                  "version":"0.4"
                }, 
                ...
            ]
        */
        try {

            res.set_content(g_EventProcessor.GetAllAsJson(), "application/json");
        } catch (const std::exception& e) {
            LOG_A(LOG_ERROR, "Error getting events: %s", e.what());
            res.status = 500;
            json error_response = {
                { "status", "error" },
                { "message", "Internal server error" }
            };
            res.set_content(error_response.dump(), "application/json");
        }
    });
    svr.Get("/api/logs/agent", [](const httplib::Request& req, httplib::Response& res) {
        // Array of Strings
        // Like. 
        /* 
           [ 
            "RedEdr 0.4",
            "Config: tracing otepad",
            "Permissions: Enabled PRIVILEGED & DEBUG",
            ]
        */
        json response = GetLogs(); // List of srings
        res.set_content(response.dump(), "application/json");
    });
    svr.Get("/api/logs/execution", [](const httplib::Request& req, httplib::Response& res) {
        // Like: 
        /* 
           {
                "pid": 0,
                "stderr": "",
                "stdout": ""
            }
        */
        json response = { 
            { "stdout", g_Executor.GetOutput() },  // String
            { "stderr", g_Executor.GetOutput() },  // String
            { "pid", 0 },
         };
        res.set_content(response.dump(), "application/json");
    });
    svr.Get("/api/logs/edr", [](const httplib::Request& req, httplib::Response& res) {
        g_EdrReader.Stop(); // Stop reading on this first call FIXME
        // Like: 
        /*
           {
               "logs":"<Events>\n</Events>",
               "edr_version":"1.0",
               "plugin_version":"1.0",
            }
        */
        json response = {
            { "logs", g_EdrReader.Get() },
            { "edr_version", "1.0" },
            { "plugin_version", "1.0" },
        };
        res.set_content(response.dump(), "application/json");
    });

    // Execute
    if (g_Config.enable_remote_exec) {
        svr.Post("/api/exec", [](const httplib::Request& req, httplib::Response& res) {
            try {
                // curl.exe -X POST http://localhost:8080/api/exec -F "file=@C:\temp\RedEdrTester.exe"
                auto file = req.get_file_value("file");
                auto filename = file.filename;
                if (file.content.empty() || filename.empty()) {
                    LOG_A(LOG_WARNING, "Webserver: Data error: %d %d", file.content.size(), filename.size());
                    res.status = 400;
                    json error_response = {
                        { "status", "error" },
                        { "message", "Invalid request: filename or file data is missing" },
                    };
                    res.set_content(error_response.dump(), "application/json");
                    return;
                }
                BOOL ret = ExecMalware(filename, file.content);
                if (!ret) {
                    res.status = 500;
                    json error_response = {
                        { "status", "error" },
                        { "message", "Failed to execute malware: "}  // TODO print exception
                    };
                    res.set_content(error_response.dump(), "application/json");
                    return;
                }
                json response = { 
                    { "status", "ok" },
                    { "pid", 0 },
                };
                res.set_content(response.dump(), "application/json");
            } catch (const std::exception& e) {
                LOG_A(LOG_ERROR, "Error in /api/exec: %s", e.what());
                res.status = 500;
                json error_response = { 
                    { "status", "error" }, 
                    { "message", "Internal server error" } 
                };
                res.set_content(error_response.dump(), "application/json");
            } catch (...) {
                LOG_A(LOG_ERROR, "Unknown error in /api/exec");
                res.status = 500;
                json error_response = {
                    { "status", "error" }, 
                    { "message", "Unknown server error" }
                };
                res.set_content(error_response.dump(), "application/json");
            }
        });
    }

    LOG_A(LOG_INFO, "WEB: Web Server listening on http://0.0.0.0:%i", webserver_port);
    
    bool listen_result = false;
    try {
        listen_result = svr.listen("0.0.0.0", webserver_port);
    } catch (const std::exception& e) {
        LOG_A(LOG_ERROR, "WEB: Server listen failed: %s", e.what());
    } catch (...) {
        LOG_A(LOG_ERROR, "WEB: Server listen failed with unknown exception");
    }
    
    if (!listen_result) {
        LOG_A(LOG_INFO, "WEB: Server listen returned false (normal during shutdown)");
    }
    
    LOG_A(LOG_INFO, "!WEB: Thread finished");
    return 0;
}


int InitializeWebServer(std::vector<HANDLE>& threads, int port) {
    webserver_port = port;
    webserver_thread = CreateThread(NULL, 0, WebserverThread, NULL, 0, NULL);
    if (webserver_thread == NULL) {
        LOG_A(LOG_ERROR, "WEB: Failed to create thread for webserver");
        return 1;
    }
    LOG_A(LOG_INFO, "!Web: Started Thread (handle %p)", webserver_thread);
    threads.push_back(webserver_thread);
    return 0;
}


void StopWebServer() {
    svr.stop();
}

