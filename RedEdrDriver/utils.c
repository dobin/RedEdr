#include <Ntifs.h>
#include <ntstrsafe.h>  // Required for RtlStringCbVPrintfA

#include "../Shared/common.h"

#define KRN_LOG_LEN 512


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
    if (pDestString->Length == 0 || pDestString->Buffer == NULL || pSubString == NULL) {
        return FALSE;
    }
    size_t lengthInWchars = pDestString->Length / sizeof(WCHAR);
    WCHAR tempBuffer[KRN_LOG_LEN];
    
    // Ensure we don't overflow the temp buffer
    if (lengthInWchars >= sizeof(tempBuffer) / sizeof(WCHAR)) {
        return FALSE;
    }
    
    // Safely copy and null-terminate
    RtlCopyMemory(tempBuffer, pDestString->Buffer, pDestString->Length);
    tempBuffer[lengthInWchars] = L'\0';
    
    int result = wcsstr(tempBuffer, pSubString) != NULL;
    return result;
}


void Unicodestring2wcharAlloc(const UNICODE_STRING* ustr, wchar_t* dest, size_t destSize)
{
    if (!ustr || !dest || destSize == 0) {
        return;  // Invalid arguments
    }
    
    size_t numChars = ustr->Length / sizeof(WCHAR);
    size_t copyLength = numChars < destSize - 1 ? numChars : destSize - 1;
    
    // Use safer kernel function
    RtlCopyMemory(dest, ustr->Buffer, copyLength * sizeof(WCHAR));
    dest[copyLength] = L'\0';
}


NTSTATUS WcharToAscii(const wchar_t* wideStr, SIZE_T wideLength, char* asciiStr, SIZE_T asciiBufferSize) {
    if (!wideStr || !asciiStr || asciiBufferSize == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    SIZE_T copyLength = wideLength < asciiBufferSize - 1 ? wideLength : asciiBufferSize - 1;
    
    for (SIZE_T i = 0; i < copyLength; ++i) {
        wchar_t wc = wideStr[i];
        if (wc < 0x80) {
            asciiStr[i] = (char)wc;  // Direct conversion for ASCII characters
        }
        else {
            asciiStr[i] = '?';  // Replace non-ASCII characters with '?'
        }
    }

    asciiStr[copyLength] = '\0';  // Null-terminate the string
    return STATUS_SUCCESS;
}


void JsonEscape(char* str, size_t buffer_size) {
    if (str == NULL || buffer_size == 0) {
        return;
    }

    size_t length = 0;
    // Find string length safely
    for (length = 0; length < buffer_size - 1 && str[length] != '\0'; ++length);

    for (size_t i = 0; i < length; ++i) {
        if (str[i] == '\\' || str[i] == '"') {
            // Check if there's enough space to shift and insert escape character
            if (length + 1 >= buffer_size) {
                return;
            }

            // Shift the remainder of the string one position to the right
            for (size_t j = length + 1; j > i; --j) {
                str[j] = str[j - 1];
            }

            // Insert escape character
            str[i] = '\\';
            ++i; // Skip over the character we just escaped
            ++length;
        }
    }
    return;
}