#include <iostream>
#include <tchar.h>
#include <windows.h>
#include <wtsapi32.h>
#include <sddl.h>

#include "logging.h"
#include "privileges.h"

bool GetUserTokenForExecution(HANDLE& hTokenDup) {
    HANDLE hToken = nullptr;
    DWORD sessionId = 0;
    WTS_SESSION_INFO* pSessionInfo = nullptr;
    DWORD sessionCount = 0;

    // Open the current process token to enable privileges
    HANDLE hProcessToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hProcessToken)) {
        std::wcerr << L"Failed to open process token, error: " << GetLastError() << std::endl;
        return false;
    }

    EnablePrivilege(hProcessToken, SE_INCREASE_QUOTA_NAME);
    EnablePrivilege(hProcessToken, SE_ASSIGNPRIMARYTOKEN_NAME);
    EnablePrivilege(hProcessToken, SE_TCB_NAME);  // Required for WTSQueryUserToken
    CloseHandle(hProcessToken);

    // Re-open to verify
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hProcessToken)) {
        std::wcerr << L"Failed to re-open process token, error: " << GetLastError() << std::endl;
        return false;
    }

    bool quota = CheckPrivilege(hProcessToken, SE_INCREASE_QUOTA_NAME);
    bool token = CheckPrivilege(hProcessToken, SE_ASSIGNPRIMARYTOKEN_NAME);
    bool tcb = CheckPrivilege(hProcessToken, SE_TCB_NAME);
    CloseHandle(hProcessToken);

    if (!quota || !token || !tcb) {
        LOG_A(LOG_ERROR, "Missing privileges (quota:%d, token:%d, tcb:%d)", quota, token, tcb);
        LOG_A(LOG_ERROR, "Must be run as SYSTEM (e.g., psexec -s -i rededr.exe)");
        return false;
    }

    // Get active session ID
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

    // Query and duplicate the user token
    if (!WTSQueryUserToken(sessionId, &hToken)) {
        DWORD err = GetLastError();
        std::wcerr << L"Failed to query user token (session " << sessionId << L"), error: " << err << std::endl;
        if (err == ERROR_PRIVILEGE_NOT_HELD) {
            std::wcerr << L"This process must be running as SYSTEM." << std::endl;
        }
        return false;
    }

    if (!DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, nullptr, SecurityImpersonation, TokenPrimary, &hTokenDup)) {
        std::wcerr << L"Failed to duplicate token, error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}


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


bool RunsAsSystem() {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return false;
    }

    DWORD size = 0;
    GetTokenInformation(hToken, TokenUser, nullptr, 0, &size);

    PTOKEN_USER pUser = (PTOKEN_USER)malloc(size);
    if (!GetTokenInformation(hToken, TokenUser, pUser, size, &size)) {
        CloseHandle(hToken);
        free(pUser);
        return false;
    }

    LPWSTR sidString = nullptr;
    ConvertSidToStringSid(pUser->User.Sid, &sidString);
    bool isSystem = (wcscmp(sidString, L"S-1-5-18") == 0); // SID for LocalSystem

    LocalFree(sidString);
    free(pUser);
    CloseHandle(hToken);
    return isSystem;
}


BOOL RunsAsSystem_bak() {
    HANDLE hToken = NULL;

    // Open the current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        std::cerr << "Failed to open process token. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Get the size of the token information
    DWORD dwBufferSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get token information size. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    // Allocate buffer for the token information
    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwBufferSize);
    if (!pTokenUser) {
        std::cerr << "Memory allocation failed." << std::endl;
        CloseHandle(hToken);
        return false;
    }

    // Retrieve the token information
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize)) {
        std::cerr << "Failed to get token information. Error: " << GetLastError() << std::endl;
        free(pTokenUser);
        CloseHandle(hToken);
        return false;
    }

    // Convert the SID to a string
    LPTSTR sidString = NULL;
    if (!ConvertSidToStringSid(pTokenUser->User.Sid, &sidString)) {
        std::cerr << "Failed to convert SID to string. Error: " << GetLastError() << std::endl;
        free(pTokenUser);
        CloseHandle(hToken);
        return false;
    }

    // Check if the SID corresponds to SYSTEM
    bool isSystem = (_tcscmp(sidString, _T("S-1-5-18")) == 0); // SYSTEM SID: S-1-5-18
    /*
    if (isSystem) {
        std::cout << "The process is running as SYSTEM." << std::endl;
    }
    else {
        std::cout << "The process is NOT running as SYSTEM. SID: " << sidString << std::endl;
    }
    */

    // Cleanup
    LocalFree(sidString);
    free(pTokenUser);
    CloseHandle(hToken);

    return isSystem;
}


bool RunsAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup)) {

        CheckTokenMembership(nullptr, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}


void PrintCurrentUser() {
    wchar_t name[256];
    DWORD size = sizeof(name) / sizeof(wchar_t);
    if (GetUserName(name, &size)) {
        std::wcout << L"User: " << name << std::endl;
    }
}


BOOL PermissionMakeMeDebug() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("Permissions: OpenProcessToken failed. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Debug too
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("Permissions: LookupPrivilegeValue failed. Error: %lu\n", GetLastError());
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; // Privileged!

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("Permissions: Could not apply specified privilege: PRIVILEGED\n");
        CloseHandle(hToken);
        return FALSE;
    }

    LOG_A(LOG_INFO, "Permissions: Enabled PRIVILEGED & DEBUG");
    CloseHandle(hToken);
    return TRUE;
}