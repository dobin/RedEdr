#pragma once
#include <stdio.h>
#include <Ntifs.h>

#define LOG_ERROR 0
#define LOG_AARNING 1
#define LOG_INFO 2
#define LOG_DEBUG 3

void LOG_A(int severity, char* format, ...);
int IsSubstringInUnicodeString(PUNICODE_STRING pDestString, PCWSTR pSubString);
void UnicodeStringToWChar(const UNICODE_STRING* ustr, wchar_t* dest, size_t destSize);
wchar_t* JsonEscape(wchar_t* str, size_t buffer_size);
