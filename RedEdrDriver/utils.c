#include <stdio.h>
#include <Ntifs.h>
#include <ntstrsafe.h>  // Required for RtlStringCbVPrintfA

#include "../Shared/common.h"

#define KRN_LOG_LEN 4096


void LOG_A(int severity, const char* format, ...)
{
    UNREFERENCED_PARAMETER(severity);
    char message[KRN_LOG_LEN] = "[RedEdr KRN] ";
    size_t offset = strlen(message);

    va_list arg_ptr;
    va_start(arg_ptr, format);

    // Use RtlStringCbVPrintfA for kernel-safe string formatting
    RtlStringCbVPrintfA(&message[offset], KRN_LOG_LEN - offset, format, arg_ptr);

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
    WCHAR tempBuffer[KRN_LOG_LEN];
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


wchar_t* JsonEscape(wchar_t* str, size_t buffer_size) {
    if (str == NULL || buffer_size == 0) {
        return str;
    }

    size_t length = 0;
    for (length = 0; str[length] != L'\0'; ++length);

    for (size_t i = 0; i < length; ++i) {
        if (str[i] == L'\\' || str[i] == L'"') {
            // Check if there's enough space to shift and insert escape character
            if (length + 1 >= buffer_size) {
                return str; // Stop processing to prevent overflow
            }

            // Shift the remainder of the string one position to the right
            for (size_t j = length + 1; j > i; --j) {
                str[j] = str[j - 1];
            }

            // Insert escape character
            str[i] = L'\\';
            ++i; // Skip over the character we just escaped
            ++length;
        }
    }
    return str;
}