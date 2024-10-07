//#include "pch.h"
#include "CppUnitTest.h"

#include "output.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace UnitTests
{
	TEST_CLASS(Output)
	{
	public:

		TEST_METHOD(TestConvertLineToJson_Dll)
		{
            std::wstring input = L"type:dll;time:133723719791285666;krn_pid:14496;func:NtOpenThread;"
                "thread_handle:0x000000642EB7F1D8;access_mask:0x5a;client_id_process:0x0000000000000000;"
                "client_id_thread:0x0000000000004ED0;callstack:[{idx:0;addr:00007FF9590993A2;page_addr:00007FF959099000;size:69632;state:0x1000;protect:0x20;type:0x1000000},"
                "{idx:4;addr:0000000000000003;page_addr:0000000000000000;size:224591872;state:0x10000;protect:0x1;type:0x0},{idx:5;addr:000000642EB7BFE0;page_addr:000000642EB7B000;"
                "size:20480;state:0x1000;protect:0x4;type:0x20000},]";
            std::wstring expect = L"{\"type\":\"dll\",\"time\":\"133723719791285666\",\"krn_pid\":\"14496\",\"func\":\"NtOpenThread\",\"thread_handle\":\"0x000000642EB7F1D8\",\"access_mask\":\"0x5a\",\"client_id_process\":\"0x0000000000000000\",\"client_id_thread\":\"0x0000000000004ED0\",\"callstack\":[{\"idx\":\"0\",\"addr\":\"00007FF9590993A2\",\"page_addr\":\"00007FF959099000\",\"size\":\"69632\",\"state\":\"0x1000\",\"protect\":\"0x20\",\"type\":\"0x1000000\"},{\"idx\":\"4\",\"addr\":\"0000000000000003\",\"page_addr\":\"0000000000000000\",\"size\":\"224591872\",\"state\":\"0x10000\",\"protect\":\"0x1\",\"type\":\"0x0\"},{\"idx\":\"5\",\"addr\":\"000000642EB7BFE0\",\"page_addr\":\"000000642EB7B000\",\"size\":\"20480\",\"state\":\"0x1000\",\"protect\":\"0x4\",\"type\":\"0x20000\"}]}";
            std::wstring result = ConvertLineToJson(input);
            Assert::AreEqual(expect.c_str(), result.c_str());
		}

        TEST_METHOD(TestConvertLineToJson_Etw)
        {
            std::wstring input = L"type:etw;time:133727141764849648;pid:6256;thread_id:7288;event:LoadImage;provider_name:Microsoft-Windows-Kernel-Process;ImageBase:0x0000029EF25623D0;ImageSize:0x0000029EF2561CA0;ProcessID:6256;ImageCheckSum:0;TimeDateStamp:1726304632;DefaultBase:0x0000029EF2561E80;ImageName:\Device\HarddiskVolume2\RedEdr\msf\loader.exe";
            std::wstring expect = L"{\"type\":\"etw\",\"time\":\"133727141764849648\",\"pid\":\"6256\",\"thread_id\":\"7288\",\"event\":\"LoadImage\",\"provider_name\":\"Microsoft-Windows-Kernel-Process\",\"ImageBase\":\"0x0000029EF25623D0\",\"ImageSize\":\"0x0000029EF2561CA0\",\"ProcessID\":\"6256\",\"ImageCheckSum\":\"0\",\"TimeDateStamp\":\"1726304632\",\"DefaultBase\":\"0x0000029EF2561E80\",\"ImageName\":\"DeviceHarddiskVolume2RedEdrmsfloader.exe\"}";
            std::wstring result = ConvertLineToJson(input);
            Assert::AreEqual(expect.c_str(), result.c_str());
        }

        TEST_METHOD(TestConvertLineToJson_Path)
        {
            std::wstring input = L"type:etw;time:133727141764849648;path:C:\\windows\\";
            std::wstring expect = L"{\"type\":\"etw\",\"time\":\"133727141764849648\",\"path\":\"C:\\windows\\\"}";
            std::wstring result = ConvertLineToJson(input);
            Assert::AreEqual(expect.c_str(), result.c_str());
        }

        TEST_METHOD(TestConvertLineToJson_Kernel)
        {
            std::wstring input = L"type:kernel;time:133727882463689912;callback:create_process;krn_pid:996;pid:1544;name:\\Device\\HarddiskVolume2\\Windows\\System32\\notepad.exe;ppid:996;parent_name:\\Device\\HarddiskVolume2\\Windows\\explorer.exe;observe:1";
            std::wstring expect = L"{\"type\":\"kernel\",\"time\":\"133727882463689912\",\"callback\":\"create_process\",\"krn_pid\":\"996\",\"pid\":\"1544\",\"name\":\"\\Device\\HarddiskVolume2\\Windows\\System32\\notepad.exe\",\"ppid\":\"996\",\"parent_name\":\"\\Device\\HarddiskVolume2\\Windows\\explorer.exe\",\"observe\":\"1\"}";
            std::wstring result = ConvertLineToJson(input);
            Assert::AreEqual(expect.c_str(), result.c_str());
        }
	};
}
