#pragma once
#include <stdio.h>
#include <Ntifs.h>

void log_message(char* format, ...);
int IsSubstringInUnicodeString(PUNICODE_STRING pDestString, PCWSTR pSubString);
void UnicodeStringToWChar(const UNICODE_STRING* ustr, wchar_t* dest, size_t destSize);
