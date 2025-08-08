
/* Shared Fsck Logging
 * 
 * Depending of where we log, we need to log differently. 
 * RedEdr.exe:          OUTPUT_STDOUT
 * RedEdrTester.exe:    OUTPUT_STDOUT
 * RedEdrDll.dll:       OUTPUT_DLL Debug
 * RedEdrPplService:    OUTPUT_PPL Debug
 * 
 * Supports: 
 *    _A: CHAR
 *    _W: WCHAR
 * 
 */

// Its easier to define here (again)
// than to include ../Shared/common.h
#define DATA_BUFFER_SIZE 8192 // all buffers for strings


#if defined OUTPUT_STDOUT

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

#elif defined OUTPUT_DLL

#include <windows.h>
#include <stdio.h>
#include "../Shared/common.h"

void LOG_A(int verbosity, const char* format, ...)
{
    char message[DATA_BUFFER_SIZE] = "[RedEdr DLL] ";
    size_t offset = strlen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vsnprintf_s(&message[offset], DATA_BUFFER_SIZE - offset, DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    OutputDebugStringA(message);
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    WCHAR message[DATA_BUFFER_SIZE] = L"[RedEdr DLL] ";
    size_t offset = wcslen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vswprintf(&message[offset], DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    OutputDebugStringW(message);
}


#elif defined OUTPUT_PPL

#include <iostream>
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include "../Shared/common.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <mutex>

static HANDLE g_logFile = INVALID_HANDLE_VALUE;
static std::mutex g_logMutex;
static bool g_logInitialized = false;

static void InitializeFileLogging() {
    if (g_logInitialized) return;
    
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logInitialized) return; // Double-check after acquiring lock
    
    // Open log file for write (this will create new or truncate existing)
    g_logFile = CreateFileA(
        "C:\\rededr\\pplservice.log",
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,  // This will create new file or truncate existing
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    g_logInitialized = true;
}

static void WriteToLogFile(const char* message) {
    InitializeFileLogging();
    
    if (g_logFile == INVALID_HANDLE_VALUE) {
        // Fallback to debug output if file can't be opened
        OutputDebugStringA(message);
        return;
    }
    
    std::lock_guard<std::mutex> lock(g_logMutex);
    
    // Get current timestamp
    using namespace std::chrono;
    auto now = system_clock::now();
    auto in_time_t = system_clock::to_time_t(now);
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    
    std::tm local_tm;
    if (localtime_s(&local_tm, &in_time_t) == 0) {
        std::ostringstream oss;
        oss << std::put_time(&local_tm, "%Y-%m-%d %H:%M:%S");
        oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        oss << " - " << message << "\r\n";
        
        std::string timestampedMessage = oss.str();
        DWORD bytesWritten;
        if (!WriteFile(g_logFile, timestampedMessage.c_str(), (DWORD)timestampedMessage.length(), &bytesWritten, NULL)) {
            // If file write fails, fallback to debug output
            OutputDebugStringA(message);
        } else {
            FlushFileBuffers(g_logFile);
        }
    } else {
        // If timestamp formatting fails, still try to write the message
        std::string simpleMessage = std::string(message) + "\r\n";
        DWORD bytesWritten;
        if (!WriteFile(g_logFile, simpleMessage.c_str(), (DWORD)simpleMessage.length(), &bytesWritten, NULL)) {
            OutputDebugStringA(message);
        } else {
            FlushFileBuffers(g_logFile);
        }
    }
}

void LOG_A(int verbosity, const char* format, ...)
{
    char message[DATA_BUFFER_SIZE] = "[RedEdr PPL] ";
    size_t offset = strlen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vsnprintf_s(&message[offset], DATA_BUFFER_SIZE - offset, DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    WriteToLogFile(message);
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    WCHAR wide_message[DATA_BUFFER_SIZE] = L"[RedEdr PPL] ";
    size_t offset = wcslen(wide_message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vswprintf(&wide_message[offset], DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    // Convert wide string to UTF-8
    char message[DATA_BUFFER_SIZE];
    int result = WideCharToMultiByte(CP_UTF8, 0, wide_message, -1, message, sizeof(message), NULL, NULL);
    if (result > 0) {
        WriteToLogFile(message);
    }
}

void CleanupFileLogging() {
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_logFile);
        g_logFile = INVALID_HANDLE_VALUE;
    }
    g_logInitialized = false;
}

#elif defined _UNITTEST

#include <iostream>
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include "../Shared/common.h"
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>

#include "CppUnitTest.h"

void LOG_A(int verbosity, const char* format, ...)
{
    char message[DATA_BUFFER_SIZE] = "[RedEdr PPL] ";
    size_t offset = strlen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vsnprintf_s(&message[offset], DATA_BUFFER_SIZE - offset, DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage(message);
    Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage("\n");

}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    WCHAR message[DATA_BUFFER_SIZE] = L"[RedEdr PPL] ";
    size_t offset = wcslen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vswprintf(&message[offset], DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage(message);
}

#elif defined _DEBUG


#include <iostream>
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include "../Shared/common.h"
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>


void LOG_A(int verbosity, const char* format, ...)
{
    char message[DATA_BUFFER_SIZE] = "[RedEdr PPL] ";
    size_t offset = strlen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vsnprintf_s(&message[offset], DATA_BUFFER_SIZE - offset, DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    printf("%s", message);
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    WCHAR message[DATA_BUFFER_SIZE] = L"[RedEdr PPL] ";
    size_t offset = wcslen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vswprintf(&message[offset], DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    printf("%s", message);
}

#else 

void LOG_A(int verbosity, const char* format, ...)
{
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
}

#endif
