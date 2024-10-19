#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>

#include "../Shared/common.h"


void PrintWcharBufferAsHex(const wchar_t* buffer, size_t bufferSize) {
    // Cast wchar_t buffer to a byte array
    const unsigned char* byteBuffer = reinterpret_cast<const unsigned char*>(buffer);

    for (size_t i = 0; i < bufferSize; ++i) {
        printf("%02X ", byteBuffer[i]);

        // Print a newline every 16 bytes for readability
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}


wchar_t* allocateAndCopyWString(const std::wstring& str) {
    size_t length = str.length();
    wchar_t* copy = new wchar_t[length + 1]; // +1 for null terminator
    std::copy(str.c_str(), str.c_str() + length + 1, copy);
    return copy;
}


// FIXME copy from dll
LARGE_INTEGER get_time() {
    FILETIME fileTime;
    LARGE_INTEGER largeInt;

    // Get the current system time as FILETIME
    GetSystemTimeAsFileTime(&fileTime);

    // Convert FILETIME to LARGE_INTEGER
    largeInt.LowPart = fileTime.dwLowDateTime;
    largeInt.HighPart = fileTime.dwHighDateTime;

    return largeInt;
}


std::wstring format_wstring(const wchar_t* format, ...) {
    wchar_t buffer[DATA_BUFFER_SIZE];

    va_list args;
    va_start(args, format);
    vswprintf(buffer, DATA_BUFFER_SIZE, format, args);
    va_end(args);

    return std::wstring(buffer);
}


std::wstring to_lowercase(const std::wstring& str) {
    std::wstring lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::towlower);
    return lower_str;
}


void remove_all_occurrences_case_insensitive(std::wstring& str, const std::wstring& to_remove) {
    std::wstring lower_str = to_lowercase(str);
    std::wstring lower_to_remove = to_lowercase(to_remove);

    size_t pos;
    while ((pos = lower_str.find(lower_to_remove)) != std::wstring::npos) {
        str.erase(pos, to_remove.length());  // Erase from the original string
        lower_str.erase(pos, lower_to_remove.length());  // Keep erasing from the lowercase copy
    }
}


std::wstring ReplaceAll(std::wstring str, const std::wstring& from, const std::wstring& to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::wstring::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}


bool contains_case_insensitive(const std::wstring& haystack, const std::wstring& needle) {
    std::wstring haystack_lower = to_lowercase(haystack);
    std::wstring needle_lower = to_lowercase(needle);
    return haystack_lower.find(needle_lower) != std::wstring::npos;
}


wchar_t* ConvertCharToWchar(const char* arg) {
    int len = MultiByteToWideChar(CP_ACP, 0, arg, -1, NULL, 0);
    wchar_t* wargv = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, arg, -1, wargv, len);
    return wargv;
}
