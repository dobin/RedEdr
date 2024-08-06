#include <iostream>
#include <fstream>
#include <string>
#include <windows.h>

#include "logreader.h"


void chomp(std::wstring& str) {
    while (!str.empty() && (str.back() == L'\n' || str.back() == L'\r')) {
        str.pop_back();
    }
}


// Helper function to move the read pointer to the end of the file
std::streampos moveToEnd(std::wifstream& file) {
    file.clear();  // Clear any potential errors
    file.seekg(0, std::ios::end);
    return file.tellg();
}


// Helper function to read and print new lines
void readNewLines(std::wifstream& file, std::streampos& lastPos) {
    file.clear();  // Clear any potential errors
    file.seekg(lastPos);  // Move to the last read position

    std::wstring buffer((std::istreambuf_iterator<wchar_t>(file)), std::istreambuf_iterator<wchar_t>());

    // Split buffer into lines and output them
    size_t start = 0;
    size_t end = buffer.find('\n');

    //printf("_");
    while (end != std::string::npos) {
        std::wstring line = buffer.substr(start, end - start);
        chomp(line);

        std::wcout << line << std::endl;
        start = end + 1;
        end = buffer.find('\n', start);
    }
    //printf(".");

    //printf("-> %d %d", start, buffer.size());

    // Output the last line if there is no trailing newline
    //if (start < buffer.size()) {
    //    std::wcout << buffer.substr(start) << std::endl;
    //}
    //printf("/");

    // Update the last position
    lastPos = file.tellg();
}


void tail_f(const std::wstring& filename) {
    std::wifstream file(filename, std::ios::in);
    if (!file.is_open()) {
        std::wcerr << "Error opening file: " << filename << std::endl;
        return;
    }

    wprintf(L"tail -f %s:\n", filename.c_str());

    std::streampos lastPos = moveToEnd(file);
    file.close();

    HANDLE hFile = CreateFile(
        filename.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcerr << "Error creating file handle: " << filename << std::endl;
        return;
    }

    HANDLE hDir = CreateFile(
        L"C:\\temp",
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        NULL
    );

    if (hDir == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating directory handle." << std::endl;
        CloseHandle(hFile);
        return;
    }

    char buffer[1024];
    DWORD bytesReturned;

    while (true) {
        if (ReadDirectoryChangesW(
            hDir,
            &buffer,
            sizeof(buffer),
            FALSE,
            FILE_NOTIFY_CHANGE_SIZE,
            &bytesReturned,
            NULL,
            NULL) == 0)
        {
            std::cerr << "Error reading directory changes." << std::endl;
            break;
        }

        file.open(filename, std::ios::in);
        if (!file.is_open()) {
            std::wcerr << "Error reopening file: " << filename << std::endl;
            break;
        }

        // Set locale to handle UTF-8
        //file.imbue(std::locale(file.getloc(),
        //    new std::codecvt_utf8<wchar_t, 0x10ffff, std::consume_header>));


        readNewLines(file, lastPos);
        file.close();
    }

    CloseHandle(hDir);
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

    tail_f(path);
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

    tail_f(path);
    return TRUE;
}