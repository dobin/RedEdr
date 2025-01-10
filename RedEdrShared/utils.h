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
char* getMemoryRegionProtect(DWORD protect);
char* getMemoryRegionType(DWORD type);
char* getMemoryRegionState(DWORD type);
std::string GetSectionPermissions(DWORD characteristics);
DWORD StartProcessInBackground(LPCWSTR exePath, LPCWSTR commandLine);
void write_file(std::string path, std::string data);
std::string get_time_for_file();

// Fuck them strings
wchar_t* string2wcharAlloc(const std::string& str); // 16
wchar_t* wstring2wcharAlloc(const std::wstring& str); // 3
wchar_t* char2wcharAlloc(char* str); // 3 for PPL, set target

std::string wstring2string(std::wstring& wide_string); // 12
std::string wchar2string(const wchar_t* wstr); // 4
std::wstring string2wstring(const std::string& str); // 3

bool contains_case_insensitive(const std::string& haystack, const std::string& needle); // 5
void remove_all_occurrences_case_insensitive(std::string& str, const std::string& to_remove); // 3
bool wstring_starts_with(const std::wstring& str, const std::wstring& prefix); // 3
wchar_t* JsonEscape(wchar_t* str, size_t buffer_size); // 9

