#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>
#include <cwchar>
#include <cstdio>
#include <sddl.h>
#include <iostream>
#include <thread>
#include <vector>

#include "../Shared/common.h"
#include "loguru.hpp"
#include "dllreader.h"
#include "output.h"
#include "utils.h"
#include "config.h"

bool InjectedDllReaderThreadStopFlag = FALSE;

HANDLE dll_pipe;
std::vector<std::thread> dll_threads; // for each connected dll client


void InjectedDllReaderStopAll() {
    InjectedDllReaderThreadStopFlag = TRUE;

    // Send some stuff so the ReadFile() in the reader thread returns
    HANDLE hPipe = CreateFile(DLL_PIPE_NAME, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) {
        // no error
        return;
    }
    DWORD dwWritten;
    BOOL success = WriteFile(hPipe, "", 0, &dwWritten, NULL);
}


void ClientHandler(HANDLE hPipe) {
    char buffer[DATA_BUFFER_SIZE];
    char* buf_ptr = buffer; // buf_ptr and rest_len are synchronized
    int rest_len = 0;
    DWORD bytesRead, bytesWritten;
    
    // send config as first packet
    // this is the only write for this pipe
    sprintf_s(buffer, DATA_BUFFER_SIZE, "callstack:%d;", g_config.do_dllinjection_ucallstack);
    if (! WriteFile(hPipe, buffer, strlen(buffer), &bytesWritten, NULL)) {
        LOG_F(ERROR, "Error when sending first message to injected DLL client. Aborting.");
        return;
    }
    memset(buffer, 0, sizeof(buffer));

    while (!InjectedDllReaderThreadStopFlag) {
        if (ReadFile(hPipe, buf_ptr, sizeof(buffer) - rest_len, &bytesRead, NULL)) {
            int full_len = rest_len + bytesRead; // full len including the previous shit, if any
            wchar_t* p = (wchar_t*)buffer; // pointer to the string we will print. points to buffer
            // which always contains the beginning of a string
            int last_potential_str_start = 0;
            for (int i = 0; i < full_len; i += 2) { // 2-byte increments because wide string
                if (buffer[i] == 0 && buffer[i + 1] == 0) { // check manually for \x00\x00
                    //wprintf(L"DLL: %s\n", p); // found \x00\x00, print the previous string
                    do_output(std::wstring(p));
                    i += 2; // skip \x00\x00
                    last_potential_str_start = i; // remember the last zero byte we found
                    p = (wchar_t*)&buffer[i]; // init p with (potential) next string
                }
            }
            if (last_potential_str_start == 0) {
                LOG_F(ERROR, "DllReader: No 0x00 0x00 byte found, errornous input?");
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
                LOG_F(INFO, "DllReader: Client disconnected: %ld", GetLastError());
                break;
            }
            else {
                LOG_F(ERROR, "DllReader: Error reading from named pipe: %ld", GetLastError());
                break;
            }
        }
    }

    DisconnectNamedPipe(hPipe);
    CloseHandle(hPipe);
}


DWORD WINAPI DllInjectionReaderProcessingThread(LPVOID param) {
    // Allow processes of all privilege levels to access this pipe
    // "D:(A;OICI;GA;;;WD)" translates to: Allow (A) All Users (WD) Generic Access (GA)
    LPCWSTR securityDescriptorString = L"D:(A;OICI;GA;;;WD)";
    SECURITY_ATTRIBUTES sa;
    PSECURITY_DESCRIPTOR pSD = NULL;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
        securityDescriptorString,
        SDDL_REVISION_1,
        &pSD,
        NULL)) {
        LOG_F(ERROR, "DllReader: Failed to create security descriptor. Error: %lu", GetLastError());
        return 1;
    }
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = pSD;
    sa.bInheritHandle = FALSE;

    // Loop which accepts new clients
    while (!InjectedDllReaderThreadStopFlag) {
        dll_pipe = CreateNamedPipe(
            DLL_PIPE_NAME,
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            0,
            &sa
        );
        if (dll_pipe == INVALID_HANDLE_VALUE) {
            LOG_F(ERROR, "DllReader: Error creating named pipe: %ld", GetLastError());
            return 1;
        }

        //LOG_F(INFO, "DllReader: Waiting for client to connect...");

        // Wait for the client to connect
        BOOL result = ConnectNamedPipe(dll_pipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (!result) {
            LOG_F(ERROR, "DllReader: Error handling client connection: %ld", GetLastError());
            CloseHandle(dll_pipe);
            continue;
        }
        LOG_F(INFO, "DllReader: Client connected (handle in new thread)");
        dll_threads.push_back(std::thread(ClientHandler, dll_pipe));
    }

    /*
    for (auto& t : dll_threads) {
        if (t.joinable()) {
            t.join();
        }
    }
    */

    LOG_F(INFO, "!DllReader: Quit");
}


void InitializeInjectedDllReader(std::vector<HANDLE>& threads) {
    const wchar_t* data = L"";
    LOG_F(INFO, "!DllReader: Start thread");
    HANDLE thread = CreateThread(NULL, 0, DllInjectionReaderProcessingThread, (LPVOID)data, 0, NULL);
    if (thread == NULL) {
        LOG_F(ERROR, "DllReader: Failed to create thread ");
        return;
    }
    threads.push_back(thread);
}
