#pragma once
#include <windows.h>
#include <stdio.h>
#include <winternl.h>  // needs to be on bottom?

// Pipe
void InitDllPipe();
void SendDllPipe(char* buffer);

// Proc
size_t LogMyStackTrace(char* buf, size_t buf_size);

// Utils
void Unicodestring2wcharAlloc(const UNICODE_STRING* ustr, wchar_t* dest, size_t destSize);

