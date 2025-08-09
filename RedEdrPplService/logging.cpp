#include <iostream>
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>

#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <mutex>

#include "../Shared/common.h"


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
        }
        else {
            FlushFileBuffers(g_logFile);
        }
    }
    else {
        // If timestamp formatting fails, still try to write the message
        std::string simpleMessage = std::string(message) + "\r\n";
        DWORD bytesWritten;
        if (!WriteFile(g_logFile, simpleMessage.c_str(), (DWORD)simpleMessage.length(), &bytesWritten, NULL)) {
            OutputDebugStringA(message);
        }
        else {
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
