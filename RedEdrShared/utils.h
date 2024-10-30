#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <winternl.h>

void PrintWcharBufferAsHex(const wchar_t* buffer, size_t bufferSize);
wchar_t* wstring2wchar(const std::wstring& str);
LARGE_INTEGER get_time();
std::wstring format_wstring(const wchar_t* format, ...);
void remove_all_occurrences_case_insensitive(std::wstring& str, const std::wstring& to_remove);
std::wstring ReplaceAll(std::wstring str, const std::wstring& from, const std::wstring& to);
std::string ReplaceAllA(std::string str, const std::string& from, const std::string& to);
bool contains_case_insensitive(const std::wstring& haystack, const std::wstring& needle);
wchar_t* ConvertCharToWchar(const char* arg);
std::string wstring_to_utf8(std::wstring& wide_string);
std::string read_file(const std::string& path);
wchar_t* getMemoryRegionProtect(DWORD protect);
wchar_t* getMemoryRegionType(DWORD type);
void UnicodeStringToWChar(const UNICODE_STRING* ustr, wchar_t* dest, size_t destSize);