#include <windows.h>
#include <stdio.h>
#include "../Shared/common.h"

void LOG_A(int verbosity, const char* format, ...)
{
    char message[DATA_BUFFER_SIZE] = "[RedEdr DLL] ";
    size_t offset = strlen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = vsnprintf_s(&message[offset], DATA_BUFFER_SIZE - offset, DATA_BUFFER_SIZE - offset, format, arg_ptr);
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