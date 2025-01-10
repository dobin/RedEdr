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
void JsonEscape(char* str, size_t buffer_size);
NTSTATUS WcharToAscii(const wchar_t* wideStr, SIZE_T wideLength, char* asciiStr, SIZE_T asciiBufferSize);
