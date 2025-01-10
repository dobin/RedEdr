#pragma once

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
#include <ctime>
#include <iomanip>

#include <string>
#include <vector>

void PrintWcharBufferAsHex(const wchar_t* buffer, size_t bufferSize);

uint64_t pointer_to_uint64(PVOID ptr);
PVOID uint64_to_pointer(uint64_t i);


uint64_t get_time();
std::string read_file(const std::string& path);
wchar_t* getMemoryRegionProtect(DWORD protect);
wchar_t* getMemoryRegionType(DWORD type);
wchar_t* getMemoryRegionState(DWORD type);
std::string GetSectionPermissions(DWORD characteristics);
DWORD StartProcessInBackground(LPCWSTR exePath, LPCWSTR commandLine);
void write_file(std::string path, std::string data);
std::string get_time_for_file();

// Fuck them strings
wchar_t* stringToWChar(const std::string& str);
wchar_t* wstring2wchar(const std::wstring& str);
wchar_t* ConvertCharToWchar(const char* arg);
std::string wcharToString(const wchar_t* wstr);
std::string wstring_to_utf8(std::wstring& wide_string);
std::wstring format_wstring(const wchar_t* format, ...);
std::wstring utf8_to_wstring(const std::string& str);

bool wstring_starts_with(const std::wstring& str, const std::wstring& prefix);
std::wstring ReplaceAll(std::wstring str, const std::wstring& from, const std::wstring& to);
std::string ReplaceAllA(std::string str, const std::string& from, const std::string& to);
bool contains_case_insensitive(const std::wstring& haystack, const std::wstring& needle);
bool contains_case_insensitive2(const std::string& haystack, const std::string& needle);
void remove_all_occurrences_case_insensitive(std::wstring& str, const std::wstring& to_remove);
void remove_all_occurrences_case_insensitive2(std::string& str, const std::string& to_remove);


wchar_t* JsonEscape(wchar_t* str, size_t buffer_size);
std::wstring JsonEscape2(PCWSTR input);
