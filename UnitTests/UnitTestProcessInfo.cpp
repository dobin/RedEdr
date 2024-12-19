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
#include "process_query.h"
#include "meminfo.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace UnitTests
{
    TEST_CLASS(MemInfoTest)
    {
    public:

        TEST_METHOD(MemInfoBasics)
        {
            TargetInfo targetInfo = TargetInfo();
			MemoryRegion* region = new MemoryRegion("test", 0x1000, 0x1000, "rwx");
			targetInfo.AddMemoryRegion(0x1000, region);
			Assert::IsTrue(targetInfo.ExistMemoryRegion(0x1000));
			Assert::IsFalse(targetInfo.ExistMemoryRegion(0x2000));

			MemoryRegion* region2 = targetInfo.GetMemoryRegion(0x1000);
			Assert::IsNotNull(region2);
			Assert::AreEqual(region2->name, region->name);
			Assert::AreEqual(region2->addr, region->addr);
			Assert::AreEqual(region2->size, region->size);
			Assert::AreEqual(region2->protection, region->protection);

			targetInfo.RemoveMemoryRegion(0x1000, 0x1000);
			Assert::IsFalse(targetInfo.ExistMemoryRegion(0x1000));
        }

        TEST_METHOD(MemInfoMultiple)
        {
			TargetInfo targetInfo = TargetInfo();
			MemoryRegion* region = new MemoryRegion("test", 0x1000, 0x1000, "rwx");
			targetInfo.AddMemoryRegion(0x1000, region);
			Assert::IsTrue(targetInfo.ExistMemoryRegion(0x1000));
			Assert::IsFalse(targetInfo.ExistMemoryRegion(0x2000));

			MemoryRegion* region2 = new MemoryRegion("test2", 0x2000, 0x1000, "rwx");
			targetInfo.AddMemoryRegion(0x2000, region2);
			Assert::IsTrue(targetInfo.ExistMemoryRegion(0x2000));
			Assert::IsFalse(targetInfo.ExistMemoryRegion(0x3000));
                
			MemoryRegion* region3 = targetInfo.GetMemoryRegion(0x2000);
			Assert::IsNotNull(region3);
			Assert::AreEqual(region3->name, region2->name);
			Assert::AreEqual(region3->addr, region2->addr);
        }

        TEST_METHOD(MemInfoUsage)
        {
            TargetInfo targetInfo = TargetInfo();
            MemoryRegion* region = new MemoryRegion("test", 0x1000, 0x1000, "rwx");
            targetInfo.AddMemoryRegion(0x1000, region);
            std::string resolved = targetInfo.ResolveStr(0x1000);
			Assert::AreEqual(resolved.c_str(), "test");
        }
    };


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
