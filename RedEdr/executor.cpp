#include <iostream>
#include <filesystem>
#include <vector>
#include <tchar.h>
#include <windows.h>
#include <wtsapi32.h>
#include <UserEnv.h>

#include "logging.h"
#include "executor.h"


bool Executor::Stop() {
	if (pihProcess == nullptr) {
		LOG_A(LOG_WARNING, "Process handle is not initialized");
		return false;
	}
    TerminateProcess(pihProcess, 1);
}


std::string Executor::GetOutput() {
	if (hStdOutRead == nullptr) {
		LOG_A(LOG_WARNING, "Output handle is not initialized");
        return "";
	}
    std::vector<char> buffer(4096);
    std::string capturedOutput;
    DWORD bytesRead;
    while (ReadFile(hStdOutRead, buffer.data(), buffer.size() - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buffer[bytesRead] = '\0';  // Null-terminate
        capturedOutput.append(buffer.data(), bytesRead);  // Append to std::string
    }
    return capturedOutput;
}


bool Executor::Start(const wchar_t* programPath) {
    HANDLE hToken = nullptr, hTokenDup = nullptr;
    DWORD sessionId = 0;
    WTS_SESSION_INFO* pSessionInfo = nullptr;
    DWORD sessionCount = 0;
    LPVOID env = nullptr;

    // Enumerate sessions to find the active user
    if (WTSEnumerateSessions(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount)) {
        for (DWORD i = 0; i < sessionCount; ++i) {
            if (pSessionInfo[i].State == WTSActive) {
                sessionId = pSessionInfo[i].SessionId;
                break;
            }
        }
        WTSFreeMemory(pSessionInfo);
    }
    else {
        std::wcerr << L"Failed to enumerate sessions, error: " << GetLastError() << std::endl;
        return false;
    }

    // Get user token for the active session
    if (!WTSQueryUserToken(sessionId, &hToken)) {
        std::wcerr << L"Failed to query user token, error: " << GetLastError() << std::endl;
        return false;
    }

    // Duplicate the token
    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &hTokenDup)) {
        std::wcerr << L"Failed to duplicate token, error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    // Create environment block
    if (!CreateEnvironmentBlock(&env, hTokenDup, TRUE)) {
        std::wcerr << L"Failed to create environment block, error: " << GetLastError() << std::endl;
        env = nullptr; // Ensure it's NULL if it fails
    }

    // Create pipes for stdout redirection
    HANDLE hStdOutWrite = nullptr;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };

    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
        std::wcerr << L"Failed to create pipe, error: " << GetLastError() << std::endl;
        CloseHandle(hTokenDup);
        CloseHandle(hToken);
        return false;
    }
    // Ensure the write handle is inheritable
    if (!SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0)) {
        std::wcerr << L"Failed to set pipe handle information, error: " << GetLastError() << std::endl;
        CloseHandle(hStdOutRead);
        CloseHandle(hStdOutWrite);
        CloseHandle(hTokenDup);
        CloseHandle(hToken);
        return false;
    }

    // Setup startup info
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi = { 0 };
    si.lpDesktop = const_cast<wchar_t*>(L"winsta0\\default"); // Required for GUI apps
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdOutWrite;
    si.hStdError = hStdOutWrite;  // Redirect stderr as well

    // Start process
    if (!CreateProcessAsUser(
        hTokenDup,      // hToken
        programPath,    // lpApplicationName
        nullptr, 	    // lpCommandLine
        nullptr,        // lpProcessAttributes
        nullptr,        // lpThreadAttributes
        FALSE,          // bInheritHandles
        CREATE_UNICODE_ENVIRONMENT,
        env,
        nullptr,
        &si,
        &pi)) {
        std::wcerr << L"Failed to create process as user, error: " << GetLastError() << std::endl;
        if (env) DestroyEnvironmentBlock(env);
        CloseHandle(hTokenDup);
        CloseHandle(hToken);
        return false;
    }
	pihProcess = pi.hProcess;

    // Close write handle to avoid blocking
    CloseHandle(hStdOutWrite);

    std::wcout << L"Process started successfully!" << std::endl;

    // Cleanup
    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hTokenDup);
    CloseHandle(hToken);

    return true;
}
