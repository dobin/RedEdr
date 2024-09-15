#pragma once

void PrintWcharBufferAsHex(const wchar_t* buffer, size_t bufferSize);
wchar_t* allocateAndCopyWString(const std::wstring& str);
LARGE_INTEGER get_time();
std::wstring format_wstring(const wchar_t* format, ...);
