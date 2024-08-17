#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <cwchar>
#include <cstdio>
#include <sddl.h>

#include "../Shared/common.h"
#include "loguru.hpp"
#include "injecteddllreader.h"


std::atomic<bool> InjectedDllReaderThreadStopFlag(false);


void InjectedDllReaderStopAll() {
    InjectedDllReaderThreadStopFlag = TRUE;
}

void PrintWcharBufferAsHex(const wchar_t* buffer, size_t bufferSize) {
    // Cast wchar_t buffer to a byte array
    const unsigned char* byteBuffer = reinterpret_cast<const unsigned char*>(buffer);

    for (size_t i = 0; i < bufferSize; ++i) {
        printf("%02X ", byteBuffer[i]);

        // Print a newline every 16 bytes for readability
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
    printf("\n");
}


DWORD WINAPI DllInjectionReaderProcessingThread(LPVOID param) {
    char buffer[DATA_BUFFER_SIZE];
    char* buf_ptr = buffer; // buf_ptr and rest_len are synchronized
    int rest_len = 0;
    memset(buffer, 0, sizeof(buffer));
    DWORD bytesRead;
    HANDLE hPipe;

    // Allow processes of all privilege levels to access this pipe
    // "D:(A;OICI;GA;;;WD)" translates to: Allow (A) All Users (WD) Generic Access (GA)
    LPCWSTR pipeName = L"\\\\.\\pipe\\MyPipe";
    LPCWSTR securityDescriptorString = L"D:(A;OICI;GA;;;WD)";
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
        securityDescriptorString,
        SDDL_REVISION_1,
        &pSD,
        NULL)) {
        printf("Failed to create security descriptor. Error: %lu\n", GetLastError());
        return 1;
    }
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    while (!InjectedDllReaderThreadStopFlag) {
        hPipe = CreateNamedPipe(
            DLL_PIPE_NAME,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            &sa
        );
        if (hPipe == INVALID_HANDLE_VALUE) {
            LOG_F(ERROR, "DllReader: Error creating named pipe: %ld", GetLastError());
            return 1;
        }

        //LOG_F(INFO, "DllReader: Waiting for client to connect...");

        // Wait for the client to connect
        BOOL result = ConnectNamedPipe(hPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!result) {
            LOG_F(ERROR, "DllReader: Error connecting to named pipe: %ld", GetLastError());
            CloseHandle(hPipe);
            return 1;
        }

        LOG_F(INFO, "DllReader: Client connected");

        while (!InjectedDllReaderThreadStopFlag) {
            if (ReadFile(hPipe, buf_ptr, sizeof(buffer) - rest_len, &bytesRead, NULL)) {
                int full_len = rest_len + bytesRead; // full len including the previous shit, if any
                wchar_t* p = (wchar_t*)buffer; // pointer to the string we will print. points to buffer
                // which always contains the beginning of a string
                int last_potential_str_start = 0;
                for (int i = 0; i < full_len; i += 2) { // 2-byte increments because wide string
                    if (buffer[i] == 0 && buffer[i + 1] == 0) { // check manually for \x00\x00
                        wprintf(L"DLL %i: %s\n", bytesRead, p); // found \x00\x00, print the previous string
                        i += 2; // skip \x00\x00
                        last_potential_str_start = i; // remember the last zero byte we found
                        p = (wchar_t*)&buffer[i]; // init p with (potential) next string
                    }
                }
                if (last_potential_str_start == 0) {
                    printf("No 0x00 0x00 byte found, errornous input?\n");
                }

                if (last_potential_str_start != full_len) {
                    // we didnt print until end of the buffer. so there's something left
                    rest_len = full_len - last_potential_str_start; // how much is left
                    memcpy(&buffer[0], &buffer[last_potential_str_start], rest_len); // copy that to the beginning of the buffer
                    buf_ptr = &buffer[rest_len]; // point read buffer to after our rest
                }
                else {
                    // printf till the end of the read data. 
                    // always reset
                    buf_ptr = &buffer[0];
                    rest_len = 0;
                }

            }
            else {
                if (GetLastError() == ERROR_BROKEN_PIPE) {
                    //LOG_F(INFO, "DllReader: Client disconnected: %ld", GetLastError());
                    break;
                }
                else {
                    LOG_F(ERROR, "DllReader: Error reading from named pipe: %ld", GetLastError());
                    break;
                }
            }
        }

        // Close the pipe
        CloseHandle(hPipe);
    }
}


void InitializeInjectedDllReader(std::vector<HANDLE>& threads) {
    const wchar_t* data = L"";
    HANDLE thread = CreateThread(NULL, 0, DllInjectionReaderProcessingThread, (LPVOID)data, 0, NULL);
    if (thread == NULL) {
        LOG_F(ERROR, "DllReader: Failed to create thread ");
        return;
    }
    threads.push_back(thread);
}
