//#include "pch.h"

#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>

#include "CppUnitTest.h"
#include "logging.h"
#include "config.h"
#include "utils.h"

#include "processcache.h"
#include "processinfo.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace UnitTests
{
    TEST_CLASS(ProcessInfoTest)
    {
    public:

        TEST_METHOD(TestProcessViaProcessCache)
        {
            Process* p;

            // PID 1 doesnt exist usually
            // But entry should still be created
            p = g_ProcessCache.getObject(1);
            Assert::IsNotNull(p);
            Assert::IsFalse(p->observe);
            
            Assert::IsTrue(g_ProcessCache.containsObject(1));

            g_config.targetExeName = L"explorer.exe";
            std::wstring processName = L"explorer.exe";
            DWORD pid = FindProcessIdByName(processName);
            Assert::IsTrue(pid > 0);
            p = g_ProcessCache.getObject(pid);
            Assert::IsNotNull(p);
            Assert::IsTrue(p->observe);
            Assert::IsTrue(contains_case_insensitive(p->image_path, processName));
        }

        TEST_METHOD(TestProcessViaMakeProcess)
        {
            std::wstring processName = L"explorer.exe";
            g_config.targetExeName = processName.c_str();
            DWORD pid = FindProcessIdByName(processName);
            Process* p = MakeProcess(pid, processName.c_str());
            
            Assert::IsTrue(pid > 0);
            p = g_ProcessCache.getObject(pid);
            Assert::IsNotNull(p);
            Assert::IsTrue(p->observe);
            Assert::IsTrue(contains_case_insensitive(p->image_path, processName));
        }

        TEST_METHOD(TestProcessNonObserverValidProcess)
        {
            std::wstring processName = L"explorer2.exe";
            g_config.targetExeName = processName.c_str();
            DWORD pid = FindProcessIdByName(L"explorer.exe");
            Process* p = MakeProcess(pid, processName.c_str());
            
            Assert::IsTrue(pid > 0);
            Assert::IsNotNull(p);
            Assert::IsFalse(p->observe);
        }

        TEST_METHOD(TestProcessNonObserverInValidProcess)
        {
            std::wstring processName = L"explorer2.exe";
            g_config.targetExeName = processName.c_str();
            DWORD pid = FindProcessIdByName(L"explorer3.exe");
            Process* p = MakeProcess(pid, processName.c_str());

            Assert::IsFalse(pid > 0);
            Assert::IsNotNull(p);
            Assert::IsFalse(p->observe);
        }
    };
}
