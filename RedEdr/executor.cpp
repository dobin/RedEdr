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

Executor g_Executor;



bool EnablePrivilege(HANDLE hToken, LPCWSTR privilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValueW(nullptr, privilege, &luid)) {
        std::wcerr << L"Failed to look up privilege " << privilege << L", error: " << GetLastError() << std::endl;
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        std::wcerr << L"Failed to adjust token privileges for " << privilege << L", error: " << GetLastError() << std::endl;
        return false;
    }

    return GetLastError() != ERROR_NOT_ALL_ASSIGNED;
}


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
        return "";
    }
    std::vector<char> buffer(4096);
    DWORD bytesRead;
    DWORD availableBytes = 0;

    LOG_A(LOG_INFO, "CapturedOutput: start");

    // Wait until data is available in the pipe
    while (true) {
        /*if (!PeekNamedPipe(hStdOutRead, nullptr, 0, nullptr, &availableBytes, nullptr)) {
            LOG_A(LOG_ERROR, "PeekNamedPipe failed, error: %d", GetLastError());
            break;
        }
        if (availableBytes == 0) {
            break;  // No more data available
        }*/

        if (!ReadFile(hStdOutRead, buffer.data(), buffer.size() - 1, &bytesRead, nullptr) || bytesRead == 0) {
			DWORD error = GetLastError();
			if (error == 109) {
                // Broken pipe is what we want...
				break;
            }
            else {
                LOG_A(LOG_INFO, "ReadFile failed, error: %d", error);
                break;
            }
        }

        buffer[bytesRead] = '\0';
        capturedOutput.append(buffer.data(), bytesRead);
    }

    LOG_A(LOG_INFO, "CapturedOutput: finish");
    return true;
}


bool CheckPrivilege(HANDLE hToken, LPCWSTR privilege) {
    PRIVILEGE_SET privSet;
    privSet.PrivilegeCount = 1;
    privSet.Control = PRIVILEGE_SET_ALL_NECESSARY;

    if (!LookupPrivilegeValueW(nullptr, privilege, &privSet.Privilege[0].Luid)) {
        std::wcerr << L"Failed to look up privilege " << privilege << L", error: " << GetLastError() << std::endl;
        return false;
    }

    BOOL hasPrivilege;
    if (!PrivilegeCheck(hToken, &privSet, &hasPrivilege)) {
        std::wcerr << L"Privilege check failed for " << privilege << L", error: " << GetLastError() << std::endl;
        return false;
    }

    return hasPrivilege;
}


void Executor::StartReaderThread() {
    std::thread readerThread([this]() {
        Capture();
        });
    readerThread.detach();
}


bool Executor::Start(const wchar_t* programPath) {
    HANDLE hToken = nullptr, hTokenDup = nullptr;
    DWORD sessionId = 0;
    WTS_SESSION_INFO* pSessionInfo = nullptr;
    DWORD sessionCount = 0;
    LPVOID env = nullptr;

    // Open the current process token
    HANDLE hProcessToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken)) {
        std::wcerr << L"Failed to open process token, error: " << GetLastError() << std::endl;
        return false;
    }
    // Enable required privileges
    EnablePrivilege(hProcessToken, SE_INCREASE_QUOTA_NAME);
    EnablePrivilege(hProcessToken, SE_ASSIGNPRIMARYTOKEN_NAME);
    EnablePrivilege(hProcessToken, SE_TCB_NAME);  // Required for WTSQueryUserToken
    CloseHandle(hProcessToken);

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hProcessToken)) {
        std::wcerr << L"Failed to open process token, error: " << GetLastError() << std::endl;
        return false;
    }
    else {
        bool quota = CheckPrivilege(hProcessToken, SE_INCREASE_QUOTA_NAME);
        bool token = CheckPrivilege(hProcessToken, SE_ASSIGNPRIMARYTOKEN_NAME);
        bool tcb = CheckPrivilege(hProcessToken, SE_TCB_NAME);
        if (!quota || !token || !tcb) {
            LOG_A(LOG_ERROR, "Failed to enable required privileges (quota:%d, token:%d, tcb:%d)", quota, token, tcb);
            LOG_A(LOG_ERROR, "Must be started as SYSTEM user (psexec -s -i rededr.exe)");
            return false;
        }
        CloseHandle(hProcessToken);
    }

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
        DWORD error = GetLastError();
        std::wcerr << L"Failed to query user token for session " << sessionId << L", error: " << error << std::endl;
        if (error == ERROR_PRIVILEGE_NOT_HELD) {
            std::wcerr << L"ERROR_PRIVILEGE_NOT_HELD: This process must be running as SYSTEM to access user tokens." << std::endl;
            std::wcerr << L"Use 'psexec -s -i rededr.exe' or run as a Windows service." << std::endl;
        }
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

    // Create pipe for capturing output
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE hStdOutWrite = nullptr;

    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &sa, 0)) {
        std::wcerr << L"Failed to create pipe, error: " << GetLastError() << std::endl;
        CloseHandle(hTokenDup);
        CloseHandle(hToken);
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
        CloseHandle(hToken);
        return false;
    }

    g_Executor.StartReaderThread();
    pihProcess = pi.hProcess;

    // Close write handle so that only the child process writes
    CloseHandle(hStdOutWrite);

    if (env) DestroyEnvironmentBlock(env);
    CloseHandle(pi.hThread);
    CloseHandle(hTokenDup);
    CloseHandle(hToken);

    return true;
}
