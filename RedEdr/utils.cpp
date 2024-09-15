#include <windows.h>
#include <iostream>
#include <vector>
#include <string>

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

