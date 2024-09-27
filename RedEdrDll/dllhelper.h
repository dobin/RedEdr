#pragma once
#include <stdio.h>
#include <winternl.h>  // needs to be on bottom?

void SendDllPipe(wchar_t* buffer);
void InitDllPipe();
LARGE_INTEGER get_time();
void UnicodeStringToWChar(const UNICODE_STRING* ustr, wchar_t* dest, size_t destSize);
void LogMyStackTrace();
