#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>

#include "logreader.h"


// Stupid but working tail-f implementation
// Just checks every second for new data
void tailFileW(const wchar_t* filePath) {
    printf("Tail -f %ls\n", filePath);

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Failed to open file. Error: %lu\n", GetLastError());
        return;
    }

    // Buffer for reading the file
    const DWORD bufferSize = 1024;
    wchar_t buffer[bufferSize / sizeof(wchar_t)];
    DWORD bytesRead;
    LARGE_INTEGER fileSize;
    LARGE_INTEGER offset;

    // Get the file size
    if (!GetFileSizeEx(hFile, &fileSize)) {
        wprintf(L"Failed to get file size. Error: %lu\n", GetLastError());
        CloseHandle(hFile);
        return;
    }

    // Start reading from the end of the file
    offset.QuadPart = fileSize.QuadPart;
    while (1) {
        // Check if there's new data
        LARGE_INTEGER newSize;
        if (!GetFileSizeEx(hFile, &newSize)) {
            wprintf(L"Failed to get file size. Error: %lu\n", GetLastError());
            break;
        }

        if (newSize.QuadPart > offset.QuadPart) {
            // Move the file pointer to the last read position
            SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN);

            // Read the new data
            if (!ReadFile(hFile, buffer, bufferSize - sizeof(wchar_t), &bytesRead, NULL)) {
                wprintf(L"Failed to read file. Error: %lu\n", GetLastError());
                break;
            }

            // Null-terminate the buffer
            buffer[bytesRead / sizeof(wchar_t)] = L'\0';

            // Print the new data
            wprintf(L"%s", buffer);

            // Update the offset
            offset.QuadPart += bytesRead;
        }

        // Sleep for a while before checking again
        Sleep(1000);
    }

    CloseHandle(hFile);
}


std::wstring findFiles(const std::wstring& directory, const std::wstring& pattern) {
    WIN32_FIND_DATA findFileData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    std::wstring fullPattern = directory + L"\\" + pattern;

    // Find the first file in the directory
    hFind = FindFirstFile(fullPattern.c_str(), &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        std::wcerr << L"No files found matching the pattern: " << pattern << std::endl;
        return L"";
    }
    else {
        do {
            //std::wcout << findFileData.cFileName << std::endl;
            return directory + L"\\" + findFileData.cFileName;
        } while (FindNextFile(hFind, &findFileData) != 0);

        DWORD dwError = GetLastError();
        FindClose(hFind);
        if (dwError != ERROR_NO_MORE_FILES) {
            std::cerr << "Error occurred while finding files: " << dwError << std::endl;
            return L"";
        }
    }
}


BOOL tail_mplog() {
    std::wstring directory;
    std::wstring pattern;

    directory = L"C:\\ProgramData\\Microsoft\\Windows Defender\\Support";
    pattern = L"MPLog-*";

    std::wstring path = findFiles(directory, pattern);
    if (path == L"") {
        std::wcerr << L"File not found" << std::endl;
        return 1;
    }

    tailFileW(path.c_str());
    return TRUE;
}


BOOL tail_testlog() {
    std::wstring directory;
    std::wstring pattern;

    directory = L"C:\\temp";
    pattern = L"test*";

    std::wstring path = findFiles(directory, pattern);
    if (path == L"") {
        std::wcerr << L"File not found" << std::endl;
        return 1;
    }

    tailFileW(path.c_str());
    return TRUE;
}