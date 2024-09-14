#include <stdio.h>
#include <Windows.h>

#include "../Shared/common.h"


VOID log_message(WCHAR* format, ...)
{
    WCHAR message[MAX_BUF_SIZE] = L"[RedEdrPplService] ";
    DWORD offset = wcslen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);
    int ret = _vsnwprintf_s(&message[offset], MAX_BUF_SIZE-offset, MAX_BUF_SIZE-offset, format, arg_ptr);
    va_end(arg_ptr);

    OutputDebugString(message);
}
