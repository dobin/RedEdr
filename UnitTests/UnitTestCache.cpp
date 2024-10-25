//#include "pch.h"

#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>

#include "CppUnitTest.h"
#include "logging.h"
#include "processcache.h"
#include "config.h"
#include "utils.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


// Helper
DWORD FindProcessId(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe)) {
        do {
            if (!_wcsicmp(pe.szExeFile, processName.c_str())) {
                processId = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
    return processId;
}


namespace UnitTests
{
    TEST_CLASS(Cache)
    {
    public:

        TEST_METHOD(TestCache)
        {
            Process* p;

            // PID 1 doesnt exist usually
            // But entry should still be created
            p = g_cache.getObject(1);
            Assert::IsNotNull(p);
            Assert::IsFalse(p->observe);
            
            Assert::IsTrue(g_cache.containsObject(1));

            // Find PID of VcxprojReader.exe, which should exist
            // And set it to be observed
            g_config.targetExeName = L"explorer.exe";
            std::wstring processName = L"explorer.exe";
            DWORD pid = FindProcessId(processName);
            Assert::IsTrue(pid > 0);
            p = g_cache.getObject(pid);
            Assert::IsNotNull(p);
            Assert::IsTrue(p->observe);
            Assert::IsTrue(contains_case_insensitive(p->image_path, processName));
        }
    };
}
