//#include "pch.h"

#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <iostream>

#include "CppUnitTest.h"
#include "logging.h"
#include "config.h"
#include "utils.h"

#include "process_resolver.h"
#include "process_mem_static.h"
#include "process_query.h"
#include "process_resolver.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace UnitTests
{
    TEST_CLASS(MemInfoTest)
    {
    public:

        TEST_METHOD(MemInfoBasics)
        {
            MemStatic memStatic = MemStatic();
			MemoryRegion* region = new MemoryRegion("test", 0x1000, 0x1000, "rwx");
			memStatic.AddMemoryRegion(0x1000, region);
			Assert::IsTrue(memStatic.ExistMemoryRegion(0x1000));
			Assert::IsFalse(memStatic.ExistMemoryRegion(0x2000));

			MemoryRegion* region2 = memStatic.GetMemoryRegion(0x1000);
			Assert::IsNotNull(region2);
			Assert::AreEqual(region2->name, region->name);
			Assert::AreEqual(region2->addr, region->addr);
			Assert::AreEqual(region2->size, region->size);
			Assert::AreEqual(region2->protection, region->protection);

			memStatic.RemoveMemoryRegion(0x1000, 0x1000);
			Assert::IsFalse(memStatic.ExistMemoryRegion(0x1000));
        }

        TEST_METHOD(MemInfoMultiple)
        {
			MemStatic memStatic = MemStatic();
			MemoryRegion* region = new MemoryRegion("test", 0x1000, 0x1000, "rwx");
			memStatic.AddMemoryRegion(0x1000, region);
			Assert::IsTrue(memStatic.ExistMemoryRegion(0x1000));
			Assert::IsFalse(memStatic.ExistMemoryRegion(0x2000));

			MemoryRegion* region2 = new MemoryRegion("test2", 0x2000, 0x1000, "rwx");
			memStatic.AddMemoryRegion(0x2000, region2);
			Assert::IsTrue(memStatic.ExistMemoryRegion(0x2000));
			Assert::IsFalse(memStatic.ExistMemoryRegion(0x3000));
                
			MemoryRegion* region3 = memStatic.GetMemoryRegion(0x2000);
			Assert::IsNotNull(region3);
			Assert::AreEqual(region3->name, region2->name);
			Assert::AreEqual(region3->addr, region2->addr);
        }

        TEST_METHOD(MemInfoUsage)
        {
            MemStatic memStatic = MemStatic();
            MemoryRegion* region = new MemoryRegion("test", 0x1000, 0x1000, "rwx");
            memStatic.AddMemoryRegion(0x1000, region);
            std::string resolved = memStatic.ResolveStr(0x1000);
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
            ProcessResolver processResolver;
            p = processResolver.getObject(1);
            Assert::IsNotNull(p);
            Assert::IsFalse(p->observe);
            Assert::IsTrue(processResolver.containsObject(1));

            // Great
			std::wstring processNameW = L"explorer.exe";
            std::string processName = "explorer.exe";

            DWORD pid = FindProcessIdByName(processNameW);
            Assert::IsTrue(pid > 0);
			processResolver.SetTargetNames({ processName });
            p = processResolver.getObject(pid);
            Assert::IsNotNull(p);
            Assert::IsTrue(p->observe);
            Assert::IsTrue(contains_case_insensitive(p->commandline, processName));
        }

        TEST_METHOD(TestProcessViaMakeProcess)
        {
            std::wstring processNameW = L"explorer.exe";
            std::string processName = "explorer.exe";

            DWORD pid = FindProcessIdByName(processNameW);
            Assert::IsTrue(pid > 0);

            Process* p = MakeProcess(pid, std::vector<std::string>{processName});
            Assert::IsNotNull(p);
            Assert::IsTrue(p->observe);
            Assert::IsTrue(contains_case_insensitive(p->commandline, processName));
        }

        TEST_METHOD(TestProcessNonObserverValidProcessViaMakeProcess)
        {
            std::wstring processNameW = L"explorer.exe";
            std::string processName_wrong = "explorer2.exe";

            DWORD pid = FindProcessIdByName(processNameW);
            Assert::IsTrue(pid > 0);

            Process* p = MakeProcess(pid, std::vector<std::string>{processName_wrong});
            Assert::IsNotNull(p);
            Assert::IsFalse(p->observe);
        }

        TEST_METHOD(TestProcessNonObserverInValidProcessViaMakeProcess)
        {
            std::wstring processNameW = L"explorer2.exe";
            std::string processName = "explorer2.exe";
            g_Config.targetProcessNames = {processName};
            DWORD pid = FindProcessIdByName(L"explorer3.exe");
            Process* p = MakeProcess(pid, std::vector<std::string>{processName});

            Assert::IsFalse(pid > 0);
            Assert::IsNotNull(p);
            Assert::IsFalse(p->observe);
        }
    };
}
