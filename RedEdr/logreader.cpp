#include <stdio.h>
#include <windows.h>
#include <dbghelp.h>
#include <wintrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <iostream>
#include <tchar.h>
#include <vector>
#include <fstream>
#include <string>
#include <tdh.h>
#include <iomanip>
#include <sstream>
#include <thread>
#include <atomic>
#include <chrono>

#include "logging.h"
#include "logreader.h"
#include "output.h"
#include "utils.h"

// Will be checked each second and exit thread if true
bool LogReaderThreadStopFlag = FALSE;


void LogReaderStopAll() {
    LogReaderThreadStopFlag = TRUE;
}


// Stupid but working tail-f implementation
// Just checks every second for new data
void tailFileW(const wchar_t* filePath) {
    LOG_A(LOG_INFO, "LOG: Tail -f %ls", filePath);

    HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_A(LOG_ERROR, "LOG: Failed to open file. Error: %lu", GetLastError());
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
        LOG_A(LOG_ERROR, "LOG: Failed to get file size. Error: %lu", GetLastError());
        CloseHandle(hFile);
        return;
    }

    // Start reading from the end of the file
    offset.QuadPart = fileSize.QuadPart;
    while (!LogReaderThreadStopFlag) {
        // Check if there's new data
        LARGE_INTEGER newSize;
        if (!GetFileSizeEx(hFile, &newSize)) {
            LOG_A(LOG_ERROR, "LOG: Failed to get file size. Error: %lu", GetLastError());
            break;
        }

        if (newSize.QuadPart > offset.QuadPart) {
            // Move the file pointer to the last read position
            SetFilePointerEx(hFile, offset, NULL, FILE_BEGIN);

            // Read the new data
            if (!ReadFile(hFile, buffer, bufferSize - sizeof(wchar_t), &bytesRead, NULL)) {
                LOG_A(LOG_INFO, "LOG: Failed to read file. Error: %lu", GetLastError());
                break;
            }

            // Null-terminate the buffer
            buffer[bytesRead / sizeof(wchar_t)] = L'\0';

            // Print the new data (including newline?)
            do_output(std::wstring(buffer));
            //wprintf(L"%s", buffer);

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
        LOG_A(LOG_ERROR, "LOG: No files found matching the pattern: %ls", pattern.c_str());
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
            LOG_A(LOG_ERROR, "LOG: Error occurred while finding files: %d", dwError);
            return L"";
        }
    }
}


DWORD WINAPI LogReaderProcessingThread(LPVOID param) {
    const wchar_t* path = (wchar_t*)param;
    LOG_A(LOG_INFO, "LOG: Start LogReaderProcessingThread: %ls", path);
    tailFileW(path);
    LOG_A(LOG_INFO, "LOG: Stopped LogReaderProcessingThread");
    return 0;
}


BOOL InitializeLogReader(std::vector<HANDLE>& threads) {
    std::wstring directory;
    std::wstring pattern;

    directory = L"C:\\ProgramData\\Microsoft\\Windows Defender\\Support";
    pattern = L"MPLog-*";

    if (TRUE) {
        directory = L"C:\\temp";
        pattern = L"test*";
    }

    std::wstring path = findFiles(directory, pattern);
    if (path == L"") {
        LOG_A(LOG_ERROR, "LOG: File not found: %ls", pattern.c_str());
        return 1;
    }

    wchar_t* real_path = allocateAndCopyWString(path);
    HANDLE thread = CreateThread(NULL, 0, LogReaderProcessingThread, (LPVOID)real_path, 0, NULL);
    if (thread == NULL) {
        LOG_A(LOG_ERROR, "LOG: Failed to create thread for trace session logreader");
        return 1;
    }
    threads.push_back(thread);

    //tailFileW(path.c_str());
    return TRUE;
}

