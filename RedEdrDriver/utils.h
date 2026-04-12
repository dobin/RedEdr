#pragma once
#include <stdio.h>
#include <Ntifs.h>


void LOG_A(int severity, char* format, ...);
int IsSubstringInUnicodeString(PUNICODE_STRING pDestString, PCWSTR pSubString);
void Unicodestring2wcharAlloc(const UNICODE_STRING* ustr, wchar_t* dest, size_t destSize);
void JsonEscape(char* str, size_t buffer_size);
NTSTATUS WcharToAscii(const wchar_t* wideStr, SIZE_T wideLength, char* asciiStr, SIZE_T asciiBufferSize);
