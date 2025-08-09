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
    int ret = vsnprintf_s(&message[offset], DATA_BUFFER_SIZE - offset, DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage(message);
    Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage("\n");

}


void LOG_W(int verbosity, const wchar_t* format, ...)
{
    WCHAR message[DATA_BUFFER_SIZE] = L"[RedEdr PPL] ";
    size_t offset = wcslen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vswprintf(&message[offset], DATA_BUFFER_SIZE - offset, format, arg_ptr);
    va_end(arg_ptr);

    Microsoft::VisualStudio::CppUnitTestFramework::Logger::WriteMessage(message);
}
