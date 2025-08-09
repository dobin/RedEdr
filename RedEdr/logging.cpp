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

#include "logging.h"
#include "loguru.hpp"

std::vector<std::string> error_messages;
std::mutex error_mutex;


std::vector <std::string> GetAgentLogs() {
    return error_messages;
}


void LOG_A(int verbosity, const char* format, ...)
{
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

    std::lock_guard<std::mutex> lock(error_mutex);

    {
        using namespace std::chrono;

        // Get current time point
        auto now = system_clock::now();
        auto in_time_t = system_clock::to_time_t(now);
        auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

        // Convert to local time using localtime_s (thread-safe)
        std::tm local_tm;
        if (localtime_s(&local_tm, &in_time_t) != 0) {
            // Fallback in case localtime_s fails
            error_messages.push_back("Failed to get local time - " + std::string(buffer));
            return;
        }

        // Format time string
        std::ostringstream oss;
        oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
        oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        oss << " - " << buffer;

        error_messages.push_back(oss.str());
    }

    //error_messages.push_back(std::string(buffer));
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
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

    std::lock_guard<std::mutex> lock(error_mutex);

    {
        using namespace std::chrono;

        // Get current time point
        auto now = system_clock::now();
        auto in_time_t = system_clock::to_time_t(now);
        auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;

        // Convert to local time using localtime_s (thread-safe)
        std::tm local_tm;
        if (localtime_s(&local_tm, &in_time_t) != 0) {
            // Fallback in case localtime_s fails
            error_messages.push_back("Failed to get local time - " + std::string(buffer));
            return;
        }

        // Format time string
        std::ostringstream oss;
        oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
        oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        oss << " - " << std::string(buffer);

        error_messages.push_back(oss.str());
    }

    //error_messages.push_back(std::string(buffer));
}
