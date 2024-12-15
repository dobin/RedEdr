#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <locale>
#include <codecvt>
#include <sstream>
#include <iostream>
#include <fstream>
#include <winternl.h>
#include <ctime>
#include <iomanip>

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


wchar_t* wstring2wchar(const std::wstring& str) {
    size_t length = str.length();
    wchar_t* copy = new wchar_t[length + 1];
    std::copy(str.c_str(), str.c_str() + length, copy);
    copy[length] = L'\0';
    return copy;
}

std::string wcharToString(const wchar_t* wstr) {
    if (!wstr) return {};
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    std::string str(size_needed - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], size_needed, nullptr, nullptr);
    return str;
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
    // +1024 needed for some reason, maybe the format string itself
    wchar_t buffer[DATA_BUFFER_SIZE+1024];

    va_list args;
    va_start(args, format);
    vswprintf(buffer, DATA_BUFFER_SIZE+1024, format, args);
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

std::string ReplaceAllA(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}

/*
std::wstring replace_all(const std::wstring& str, const std::wstring& from, const std::wstring& to) {
    std::wstring result = str;
    if (from.empty()) return result;
    size_t start_pos = 0;
    while ((start_pos = result.find(from, start_pos)) != std::wstring::npos) {
        result.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
    return result;
}
*/


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


// Dear mother of god whats up with all these goddamn string types
wchar_t* stringToWChar(const std::string& str) {
    if (str.empty()) {
        wchar_t* empty = new wchar_t[1];
        empty[0] = L'\0';
        return empty;
    }
    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    if (sizeNeeded <= 0) {
        throw std::runtime_error("Error converting string to wchar_t*");
    }
    wchar_t* wideString = new wchar_t[sizeNeeded];
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wideString, sizeNeeded);
    return wideString;
}


std::string wstring_to_utf8(std::wstring& wide_string) {
    if (wide_string.empty()) {
        return {};
    }

    // Determine the size needed for the UTF-8 buffer
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size_needed <= 0) {
        throw std::runtime_error("Failed to calculate size for UTF-8 string.");
    }

    // Allocate the buffer and perform the conversion
    std::string utf8_string(size_needed - 1, '\0'); // Exclude the null terminator
    WideCharToMultiByte(CP_UTF8, 0, wide_string.c_str(), -1, &utf8_string[0], size_needed, nullptr, nullptr);

    return utf8_string;
}


/*
    std::wstring_convert<std::codecvt_utf8<wchar_t>> conv;
    return conv.to_bytes(output.str());
*/


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


void write_file(std::string path, std::string data) {
	std::ofstream file(path);
    if (!file.is_open()) {
        std::cerr << "Could not open file: " << path << std::endl;
        return;
    }
	file << data;
	file.close();
}


std::string get_time_for_file() {
    std::time_t now = std::time(nullptr);
    std::tm tm = {};
    if (localtime_s(&tm, &now) != 0) {
        throw std::runtime_error("Failed to get local time");
    }
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d-%H-%M-%S");
    return oss.str();
}


wchar_t* getMemoryRegionProtect(DWORD protect) {
    const wchar_t* memoryProtect;
    switch (protect) {
	case PAGE_EXECUTE:
		memoryProtect = L"--X";
		break;
	case PAGE_EXECUTE_READ:
		memoryProtect = L"R-X";
		break;
	case PAGE_EXECUTE_READWRITE:
		memoryProtect = L"RWX";
		break;
	case PAGE_EXECUTE_WRITECOPY:
		memoryProtect = L"EXECUTE_WRITECOPY";
		break;
	case PAGE_NOACCESS:
		memoryProtect = L"NOACCESS";
		break;
	case PAGE_READONLY:
		memoryProtect = L"R--";
		break;
	case PAGE_READWRITE:
		memoryProtect = L"RW-";
		break;
	case PAGE_WRITECOPY:
		memoryProtect = L"WRITECOPY";
		break;
    case PAGE_GUARD:
        memoryProtect = L"GUARD";
		break;
    case PAGE_NOCACHE:
		memoryProtect = L"NOCACHE";
        break;
	case PAGE_WRITECOMBINE:
        memoryProtect = L"WRITECOMBINE";
        break;
	default:
		memoryProtect = L"Unknown";
		break;
	}
	return (wchar_t*) memoryProtect;
}


wchar_t* getMemoryRegionType(DWORD type) {
    const wchar_t* memoryType;
    switch (type) {
    case MEM_IMAGE:
        memoryType = L"IMAGE";
        break;
    case MEM_MAPPED:
        memoryType = L"MAPPED";
        break;
    case MEM_PRIVATE:
        memoryType = L"PRIVATE";
        break;
    default:
        memoryType = L"Unknown";
        break;
    }
    return (wchar_t*)memoryType;
}


wchar_t* getMemoryRegionState(DWORD type) {
    const wchar_t* memoryType;
    switch (type) {
    case MEM_FREE:
        memoryType = L"FREE";
        break;
    case MEM_RESERVE:
        memoryType = L"RESERVE";
        break;
    case MEM_COMMIT:
        memoryType = L"COMMIT";
        break;
    default:
        memoryType = L"Unknown";
        break;
    }
    return (wchar_t*) memoryType;
}


wchar_t* GetMemoryPermissions_Unused(wchar_t* buf, DWORD protection) {
    //char permissions[4] = "---"; // Initialize as "---"
    wcscpy_s(buf, 16, L"---");

    if (protection & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[0] = L'R'; // Readable
    }
    if (protection & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[1] = L'W'; // Writable
    }
    if (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
        buf[2] = L'X'; // Executable
    }
    buf[3] = L'\x00';

    return buf;
}


void UnicodeStringToWChar(const UNICODE_STRING* ustr, wchar_t* dest, size_t destSize)
{
    if (!ustr || !dest || destSize == 0) {
        return;  // Invalid arguments or destination size is zero
    }

    // Ensure that the source UNICODE_STRING is valid
    if (ustr->Length == 0 || ustr->Buffer == NULL) {
        dest[0] = L'\0';  // Set dest to an empty string
        return;
    }

    // Get the number of characters to copy (Length is in bytes, so divide by sizeof(WCHAR))
    size_t numChars = ustr->Length / sizeof(WCHAR);

    // Copy length should be the smaller of the available characters or the destination size minus 1 (for null terminator)
    size_t copyLength = (numChars < destSize - 1) ? numChars : destSize - 1;

    // Use wcsncpy_s to safely copy the string
    wcsncpy_s(dest, destSize, ustr->Buffer, copyLength);

    // Ensure the destination string is null-terminated
    dest[copyLength] = L'\0';
}


wchar_t* JsonEscape(wchar_t* str, size_t buffer_size) {
    if (str == NULL || buffer_size == 0) {
        str;
    }

    size_t length = 0;
    for (length = 0; str[length] != L'\0'; ++length);

    for (size_t i = 0; i < length; ++i) {
        if (str[i] == L'\\' || str[i] == L'"') {
            // Check if there's enough space to shift and insert escape character
            if (length + 1 >= buffer_size) {
                return str; // Stop processing to prevent overflow
            }

            // Shift the remainder of the string one position to the right
            for (size_t j = length + 1; j > i; --j) {
                str[j] = str[j - 1];
            }

            // Insert escape character
            str[i] = L'\\';
            ++i; // Skip over the character we just escaped
            ++length;
        }
    }
    return str;
}


std::wstring JsonEscape2(PCWSTR input) {
    std::wstring result;

    while (*input) {
        if (*input == L'"') {
            result += L"\\\"";  // Escape double quotes (")
        }
        else if (*input == L'\\') {
            result += L"\\\\";  // Escape backslashes (\)
        }
        else {
            result += *input;  // Add regular character
        }
        ++input;
    }

    return result;
}


DWORD StartProcessInBackground(LPCWSTR exePath, LPCWSTR commandLine) {
    STARTUPINFO si = { 0 };
    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; // Start the process in the background

    PROCESS_INFORMATION pi = { 0 };

    // Combine exePath and commandLine into a single buffer
    std::wstring fullCommand = std::wstring(exePath) + L" " + std::wstring(commandLine);
    std::vector<wchar_t> commandBuffer(fullCommand.begin(), fullCommand.end());
    commandBuffer.push_back(0); // Null-terminate the buffer

    // Create the process
    if (CreateProcess(
        nullptr,                 // Application name (null to use command line)
        commandBuffer.data(),    // Command line
        nullptr,                 // Process security attributes
        nullptr,                 // Thread security attributes
        FALSE,                   // Inherit handles
        CREATE_NO_WINDOW,        // Creation flags
        nullptr,                 // Use parent's environment block
        nullptr,                 // Use parent's current directory
        &si,                     // Pointer to STARTUPINFO
        &pi                      // Pointer to PROCESS_INFORMATION
    )) {
        DWORD pid = pi.dwProcessId; // Retrieve the process ID

        // Close handles to avoid resource leaks
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return pid;
    }
    else {
        // Print error and return 0 if process creation failed
        std::wcerr << L"Failed to start process. Error: " << GetLastError() << std::endl;
        return 0;
    }
}
