
/* Shared Fsck Logging
 * 
 * Depending of where we log, we need to log differently. 
 * RedEdr.exe:          OUTPUT_STDOUT
 * RedEdrTester.exe:    OUTPUT_STDOUT
 * RedEdrDll.dll:       OUTPUT_DLL Debug
 * RedEdrPplService:    OUTPUT_PPL Debug
 * 
 * Supports: 
 *    _A: CHAR
 *    _W: WCHAR
 * 
 */

// Its easier to define here (again)
// than to include ../Shared/common.h
#define DATA_BUFFER_SIZE 8192 // all buffers for strings


#if defined OUTPUT_STDOUT

#include <iostream>
#include <windows.h>

#include "logging.h"
#include "loguru.hpp"


void LOG_A(int verbosity, const char* format, ...)
{
    va_list args;
    va_start(args, format);
    char buffer[DATA_BUFFER_SIZE] = { 0 };
    vsnprintf_s(buffer, sizeof(buffer), format, args);
    //printf("%s\n", buffer);
    switch (verbosity) {
    case LOG_ERROR:
        LOG_F(ERROR, "%s", buffer);
        break;

    case LOG_WARNING:
        LOG_F(WARNING, "%s", buffer);
        break;

    case LOG_INFO:
        LOG_F(INFO, "%s", buffer);
        break;

    case LOG_DEBUG:
        LOG_F(INFO, "%s", buffer);
        break;
    }
    va_end(args);
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    va_list args;
    va_start(args, format);
    wchar_t wide_buffer[DATA_BUFFER_SIZE];
    vswprintf_s(wide_buffer, sizeof(wide_buffer) / sizeof(wchar_t), format, args);
    char buffer[DATA_BUFFER_SIZE];
    int result = WideCharToMultiByte(CP_UTF8, 0, wide_buffer, -1, buffer, sizeof(buffer), NULL, NULL);
    
    switch (verbosity) {
    case LOG_ERROR:
        LOG_F(ERROR, "%s", buffer);
        break;

    case LOG_WARNING:
        LOG_F(WARNING, "%s", buffer);
        break;

    case LOG_INFO:
        LOG_F(INFO, "%s", buffer);
        break;

    case LOG_DEBUG:
        LOG_F(INFO, "%s", buffer);
        break;
    }
    va_end(args);
}

#elif defined OUTPUT_DLL

#include <windows.h>
#include <stdio.h>
#include "../Shared/common.h"

void LOG_A(int verbosity, const char* format, ...)
{
    char message[DATA_BUFFER_SIZE] = "[RedEdr DLL] ";
    size_t offset = strlen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vsnprintf_s(&message[offset], DATA_BUFFER_SIZE - offset, MAX_BUF_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    OutputDebugStringA(message);
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    WCHAR message[DATA_BUFFER_SIZE] = L"[RedEdr DLL] ";
    size_t offset = wcslen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vswprintf(&message[offset], DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    OutputDebugStringW(message);
}


#elif defined OUTPUT_PPL

#include <iostream>
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include "../Shared/common.h"

void LOG_A(int verbosity, const char* format, ...)
{
    char message[DATA_BUFFER_SIZE] = "[RedEdr PPL] ";
    size_t offset = strlen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vsnprintf_s(&message[offset], DATA_BUFFER_SIZE - offset, MAX_BUF_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    OutputDebugStringA(message);
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    WCHAR message[DATA_BUFFER_SIZE] = L"[RedEdr PPL] ";
    size_t offset = wcslen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vswprintf(&message[offset], DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    OutputDebugString(message);
}

#elif defined _UNITTEST

#include <iostream>
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include "../Shared/common.h"
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>

#include "CppUnitTest.h"

void LOG_A(int verbosity, const char* format, ...)
{
    char message[DATA_BUFFER_SIZE] = "[RedEdr PPL] ";
    size_t offset = strlen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vsnprintf_s(&message[offset], DATA_BUFFER_SIZE - offset, MAX_BUF_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage(message);
    Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage("\n");

}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    WCHAR message[WCHAR_BUFFER_SIZE] = L"[RedEdr PPL] ";
    size_t offset = wcslen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vswprintf(&message[offset], WCHAR_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage(message);
}

#elif defined _DEBUG


#include <iostream>
#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include "../Shared/common.h"
#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>


void LOG_A(int verbosity, const char* format, ...)
{
    char message[DATA_BUFFER_SIZE] = "[RedEdr PPL] ";
    size_t offset = strlen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vsnprintf_s(&message[offset], DATA_BUFFER_SIZE - offset, MAX_BUF_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    printf("%s", message);
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    WCHAR message[WCHAR_BUFFER_SIZE] = L"[RedEdr PPL] ";
    size_t offset = wcslen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vswprintf(&message[offset], WCHAR_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    printf("%s", message);
}

#else 

void LOG_A(int verbosity, const char* format, ...)
{
}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
}

#endif
