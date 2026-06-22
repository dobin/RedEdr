#include <iostream>
#include <windows.h>
#include <vector>
#include <string>
#include <mutex>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <fstream>

#include "logging.h"
#include "loguru.hpp"

std::vector<std::string> error_messages;
std::mutex error_mutex;
std::ofstream log_file;

#define DO_LOG_DEBUG 0


// Forward declaration: AppendAgentLog (below) uses InitLogFile, which is
// defined further down in this file.
void InitLogFile();


// Append a pre-formatted message to the agent log store (error_messages)
// and the log file, with a timestamp prefix matching LOG_A's format.
// Caller must NOT hold error_mutex.
static void AppendAgentLog(const std::string& message)
{
    std::lock_guard<std::mutex> lock(error_mutex);

    using namespace std::chrono;

    auto now = system_clock::now();
    auto in_time_t = system_clock::to_time_t(now);
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

    std::tm local_tm;
    if (localtime_s(&local_tm, &in_time_t) != 0) {
        error_messages.push_back("Failed to get local time - " + message);
        return;
    }

    // Log to: stdout
    std::ostringstream oss;
    oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    oss << " - " << message;

    // Log to: in-memory store (error_messages)
    std::string log_entry = oss.str();
    error_messages.push_back(log_entry);

    // Log to: .log file
    InitLogFile();
    if (log_file.is_open()) {
        log_file << log_entry << std::endl;
        log_file.flush();
    }
}


// Public entry point for external log sources (e.g. kernel-log ETW reader).
void AddAgentLog(const std::string& message)
{
    AppendAgentLog(message);
}

// Initialize log file
void InitLogFile() {
    static bool initialized = false;
    if (!initialized) {
        // Create directory if it doesn't exist
        CreateDirectoryA("c:\\rededr", NULL);
        log_file.open("c:\\rededr\\rededr.log", std::ios::app);
        initialized = true;
    }
}


std::vector <std::string> GetAgentLogs() {
    return error_messages;
}


void LOG_A(int verbosity, const char* format, ...)
{
    if (!DO_LOG_DEBUG && verbosity == LOG_DEBUG) {
        return;
    }

    va_list args;
    va_start(args, format);
    char buffer[DATA_BUFFER_SIZE] = { 0 };
    vsnprintf_s(buffer, sizeof(buffer), format, args);
    //printf("%s\n", buffer);
    switch (verbosity) {
    case LOG_ERROR:
        LOG_F(ERROR, "%s", buffer);
        break;

    case LOG_WARNING:
        LOG_F(WARNING, "%s", buffer);
        break;

    case LOG_INFO:
        LOG_F(INFO, "%s", buffer);
        break;

    case LOG_DEBUG:
        LOG_F(INFO, "%s", buffer);
        break;
    }
    va_end(args);

    AppendAgentLog(buffer);
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    if (!DO_LOG_DEBUG && verbosity == LOG_DEBUG) {
        return;
    }

    va_list args;
    va_start(args, format);
    wchar_t wide_buffer[DATA_BUFFER_SIZE];
    vswprintf_s(wide_buffer, sizeof(wide_buffer) / sizeof(wchar_t), format, args);
    char buffer[DATA_BUFFER_SIZE];
    int result = WideCharToMultiByte(CP_UTF8, 0, wide_buffer, -1, buffer, sizeof(buffer), NULL, NULL);

    switch (verbosity) {
    case LOG_ERROR:
        LOG_F(ERROR, "%s", buffer);
        break;

    case LOG_WARNING:
        LOG_F(WARNING, "%s", buffer);
        break;

    case LOG_INFO:
        LOG_F(INFO, "%s", buffer);
        break;

    case LOG_DEBUG:
        LOG_F(INFO, "%s", buffer);
        break;
    }
    va_end(args);

    AppendAgentLog(buffer);
}
