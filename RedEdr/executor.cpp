#include <iostream>
#include <filesystem>
#include <vector>
#include <tchar.h>
#include <windows.h>
#include <wtsapi32.h>
#include <UserEnv.h>
#include <thread>

#include "logging.h"
#include "executor.h"
#include "privileges.h"

Executor g_Executor;



bool Executor::Stop() {
	if (pihProcess == nullptr) {
		LOG_A(LOG_WARNING, "Process handle is not initialized");
		return false;
	}
    TerminateProcess(pihProcess, 1);
    return true;
}


std::string Executor::GetOutput() {
    return capturedOutput;
}


bool Executor::Capture() {
    if (hStdOutRead == nullptr) {
        LOG_A(LOG_WARNING, "Output handle is not initialized");
        return false;
    }

    std::vector<char> buffer(4096);
    DWORD bytesRead = 0;
    DWORD availableBytes = 0;

    LOG_A(LOG_INFO, "CapturedOutput: start");

    while (true) {
        // Check if there's data to read
        if (!PeekNamedPipe(hStdOutRead, nullptr, 0, nullptr, &availableBytes, nullptr)) {
            //LOG_A(LOG_ERROR, "PeekNamedPipe failed, error: %d", GetLastError());
            break;
        }

        if (availableBytes == 0) {
            // Check if the process is done
            DWORD exitCode = 0;
            if (!GetExitCodeProcess(pihProcess, &exitCode) || exitCode != STILL_ACTIVE) {
                break; // Process has exited
            }
            Sleep(50); // Wait a bit before checking again
            continue;
        }

        // Read the available output
        if (!ReadFile(hStdOutRead, buffer.data(), buffer.size() - 1, &bytesRead, nullptr) || bytesRead == 0) {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE || error == ERROR_HANDLE_EOF) {
                break; // Pipe closed, process exited
            }
            else {
                LOG_A(LOG_ERROR, "ReadFile failed, error: %d", error);
                break;
            }
        }

        buffer[bytesRead] = '\0';
        capturedOutput.append(buffer.data(), bytesRead);
    }

    LOG_A(LOG_INFO, "CapturedOutput: finish");
    return true;
}


void Executor::StartReaderThread() {
    std::thread readerThread([this]() {
        Capture();
        });
    readerThread.detach();
}


bool Executor::StartAsSystem(const wchar_t* programPath) {
    HANDLE hTokenDup = nullptr;
    LPVOID env = nullptr;

    if (!GetUserTokenForExecution(hTokenDup)) {
        return false;
    }

    // Create environment block
    if (!CreateEnvironmentBlock(&env, hTokenDup, TRUE)) {
        std::wcerr << L"Failed to create environment block, error: " << GetLastError() << std::endl;
        env = nullptr; // Ensure it's NULL if it fails
    }

    // Create pipe for capturing output
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE hStdOutWrite = nullptr;

    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
        std::wcerr << L"Failed to create pipe, error: " << GetLastError() << std::endl;
        CloseHandle(hTokenDup);
        return false;
    }

    // Ensure read handle is not inheritable, write handle is inheritable
    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi = { 0 };
    si.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdOutWrite;

    if (!CreateProcessAsUser(hTokenDup, programPath, nullptr, nullptr, nullptr, TRUE,
        CREATE_UNICODE_ENVIRONMENT, env, nullptr, &si, &pi)) {
        std::wcerr << L"Failed to create process as user, error: " << GetLastError() << std::endl;
        if (env) DestroyEnvironmentBlock(env);
        CloseHandle(hTokenDup);
        return false;
    }

    g_Executor.StartReaderThread();
    pihProcess = pi.hProcess;

    // Close write handle so that only the child process writes
    CloseHandle(hStdOutWrite);

    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(pi.hThread);
    CloseHandle(hTokenDup);

    return true;
}


bool Executor::StartAsUser(const wchar_t* programPath) {
    // Create pipe for capturing output
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE hStdOutWrite = nullptr;

    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
        std::wcerr << L"Failed to create pipe, error: " << GetLastError() << std::endl;
        return false;
    }

    // Prevent the read end from being inherited
    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi = { 0 };

    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdOutWrite;

    // Optional: set desktop if needed
    si.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default");

    if (!CreateProcess(
        programPath,      // Application name
        nullptr,          // Command line
        nullptr,          // Process security
        nullptr,          // Thread security
        TRUE,             // Inherit handles
        0,                // Creation flags
        nullptr,          // Environment
        nullptr,          // Current directory
        &si,              // Startup info
        &pi               // Process info
    )) {
        std::wcerr << L"Failed to create process, error: " << GetLastError() << std::endl;
        CloseHandle(hStdOutWrite);
        return false;
    }

    // Store hProcess for later use
    pihProcess = pi.hProcess;

    // Start the thread to read from hStdOutRead
    g_Executor.StartReaderThread();

    // Close the write end in parent so only child writes
    CloseHandle(hStdOutWrite);
    CloseHandle(pi.hThread);

    return true;
}


bool Executor::Start(const wchar_t* programPath) {
    if (RunsAsSystem()) {
		return StartAsSystem(programPath);
    }
    else {
        return StartAsUser(programPath);
    }
}


bool Executor::KillLastExec() {
    if (pihProcess == nullptr) {
        LOG_A(LOG_WARNING, "No process to kill, pihProcess is NULL");
        return false;
    }
    if (!TerminateProcess(pihProcess, 1)) {
        LOG_A(LOG_ERROR, "Failed to terminate process, error: %d", GetLastError());
        return false;
    }
    CloseHandle(pihProcess);
    pihProcess = nullptr;
    capturedOutput.clear();
    return true;
}
