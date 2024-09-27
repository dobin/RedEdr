#include <stdio.h>
#include <Ntifs.h>
#include <ntstrsafe.h>  // Required for RtlStringCbVPrintfA

#include "../Shared/common.h"


void LOG_A(int severity, const char* format, ...)
{
    UNREFERENCED_PARAMETER(severity);
    char message[MAX_BUF_SIZE] = "[RedEdr KRN] ";
    size_t offset = strlen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);

    // Use RtlStringCbVPrintfA for kernel-safe string formatting
    RtlStringCbVPrintfA(&message[offset], MAX_BUF_SIZE - offset, format, arg_ptr);

    va_end(arg_ptr);

    // Use DbgPrintEx for kernel logging
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s", message);
}


// TODO SLOW
int IsSubstringInUnicodeString(PUNICODE_STRING pDestString, PCWSTR pSubString) {
    if (pDestString->Length == 0 || pDestString->Buffer == NULL) {
        return FALSE;
    }
    size_t lengthInWchars = pDestString->Length / sizeof(WCHAR);
    WCHAR tempBuffer[1024];
    if (lengthInWchars >= sizeof(tempBuffer) / sizeof(WCHAR)) {
        return FALSE;
    }
    memcpy(tempBuffer, pDestString->Buffer, pDestString->Length);
    tempBuffer[lengthInWchars] = L'\0';
    int result = wcsstr(tempBuffer, pSubString) != NULL;
    return result;
}


void UnicodeStringToWChar(const UNICODE_STRING* ustr, wchar_t* dest, size_t destSize)
{
    if (!ustr || !dest) {
        return;  // Invalid arguments
    }
    size_t numChars = ustr->Length / sizeof(WCHAR);
    size_t copyLength = numChars < destSize - 1 ? numChars : destSize - 1;
    wcsncpy(dest, ustr->Buffer, copyLength);
    dest[copyLength] = L'\0';
}
