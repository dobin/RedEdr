//#include "pch.h"
#include "CppUnitTest.h"

#include "eventproducer.h"
#include "utils.h"
#include "json.hpp"
#include "logging.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace UnitTests
{
	TEST_CLASS(EventProducerTest)
	{
	public:
        TEST_METHOD(ConvertWstringToString) {
            std::wstring input = L"Hello\\World";
            std::string reference = "Hello\\World";

			std::string result = wstring_to_utf8(input);
			Assert::AreEqual(reference.c_str(), result.c_str());
        }
        TEST_METHOD(ConvertWstringToString2) {
            std::wstring input = L"Hello\\\\World";
            std::string reference = "Hello\\\\World";

            std::string result = wstring_to_utf8(input);
            Assert::AreEqual(reference.c_str(), result.c_str());
        }

		TEST_METHOD(TestConvertLineToJson_Dll)
		{
            std::wstring input = L"type:dll;time:133723719791285666;krn_pid:14496;func:NtOpenThread;"
                "thread_handle:0x000000642EB7F1D8;access_mask:0x5a;client_id_process:0x0000000000000000;"
                "client_id_thread:0x0000000000004ED0;callstack:[{idx:0;addr:00007FF9590993A2;page_addr:00007FF959099000;size:69632;state:0x1000;protect:0x20;type:0x1000000},"
                "{idx:4;addr:0000000000000003;page_addr:0000000000000000;size:224591872;state:0x10000;protect:0x1;type:0x0},{idx:5;addr:000000642EB7BFE0;page_addr:000000642EB7B000;"
                "size:20480;state:0x1000;protect:0x4;type:0x20000},]";
            std::string expect = "{\"type\":\"dll\",\"time\":\"133723719791285666\",\"krn_pid\":\"14496\",\"func\":\"NtOpenThread\",\"thread_handle\":\"0x000000642EB7F1D8\",\"access_mask\":\"0x5a\",\"client_id_process\":\"0x0000000000000000\",\"client_id_thread\":\"0x0000000000004ED0\",\"callstack\":[{\"idx\":\"0\",\"addr\":\"00007FF9590993A2\",\"page_addr\":\"00007FF959099000\",\"size\":\"69632\",\"state\":\"0x1000\",\"protect\":\"0x20\",\"type\":\"0x1000000\"},{\"idx\":\"4\",\"addr\":\"0000000000000003\",\"page_addr\":\"0000000000000000\",\"size\":\"224591872\",\"state\":\"0x10000\",\"protect\":\"0x1\",\"type\":\"0x0\"},{\"idx\":\"5\",\"addr\":\"000000642EB7BFE0\",\"page_addr\":\"000000642EB7B000\",\"size\":\"20480\",\"state\":\"0x1000\",\"protect\":\"0x4\",\"type\":\"0x20000\"}]}";
            
            EventProducer eventProducer;
            std::string result = eventProducer.ConvertLogLineToJsonEvent(input);
            Assert::AreEqual(expect.c_str(), result.c_str());
		}

        TEST_METHOD(TestConvertLineToJson_Etw)
        {
            std::wstring input = L"type:etw;time:133727141764849648;pid:6256;thread_id:7288;event:LoadImage;provider_name:Microsoft-Windows-Kernel-Process;ImageBase:0x0000029EF25623D0;ImageSize:0x0000029EF2561CA0;ProcessID:6256;ImageCheckSum:0;TimeDateStamp:1726304632;DefaultBase:0x0000029EF2561E80;ImageName:\\\\Device\\Harddisk\\Volume2\\RedEdr\\msf\\loader.exe";
            std::string expect = "{\"type\":\"etw\",\"time\":\"133727141764849648\",\"pid\":\"6256\",\"thread_id\":\"7288\",\"event\":\"LoadImage\",\"provider_name\":\"Microsoft-Windows-Kernel-Process\",\"ImageBase\":\"0x0000029EF25623D0\",\"ImageSize\":\"0x0000029EF2561CA0\",\"ProcessID\":\"6256\",\"ImageCheckSum\":\"0\",\"TimeDateStamp\":\"1726304632\",\"DefaultBase\":\"0x0000029EF2561E80\",\"ImageName\":\"\\\\\\\\Device\\\\Harddisk\\\\Volume2\\\\RedEdr\\\\msf\\\\loader.exe\"}";

            EventProducer eventProducer;
            std::string result = eventProducer.ConvertLogLineToJsonEvent(input);
            Assert::AreEqual(expect.c_str(), result.c_str());
        }

        TEST_METHOD(TestConvertLineToJson_Path)
        {
            std::wstring input = L"type:etw;time:133727141764849648;path:C:\\windows\\";
            std::string expect = "{\"type\":\"etw\",\"time\":\"133727141764849648\",\"path\":\"C:\\\\windows\\\\\"}";

            EventProducer eventProducer;
            std::string result = eventProducer.ConvertLogLineToJsonEvent(input);
            Assert::AreEqual(expect.c_str(), result.c_str());
        }

        TEST_METHOD(TestConvertLineToJson_Kernel)
        {
            std::wstring input = L"type:kernel;time:133727882463689912;callback:process_create;krn_pid:996;pid:1544;name:\\Device\\HarddiskVolume2\\Windows\\System32\\notepad.exe;ppid:996;parent_name:\\Device\\HarddiskVolume2\\Windows\\explorer.exe;observe:1";
            std::string expect = "{\"type\":\"kernel\",\"time\":\"133727882463689912\",\"callback\":\"process_create\",\"krn_pid\":\"996\",\"pid\":\"1544\",\"name\":\"\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\System32\\\\notepad.exe\",\"ppid\":\"996\",\"parent_name\":\"\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\explorer.exe\",\"observe\":\"1\"}";

            EventProducer eventProducer;
            std::string result = eventProducer.ConvertLogLineToJsonEvent(input);
            Assert::AreEqual(expect.c_str(), result.c_str());
        }

        TEST_METHOD(TestConvertLineToJson_Peb)
        {
            std::wstring input = L"type:peb;time:133727882463779926;id:1544;parent_pid:996;image_path:C:\\Windows\\system32\\notepad.exe;commandline:\"C:\\Windows\\system32\\notepad.exe\" ;working_dir:C:\\Users\\hacker\\;is_debugged:0;is_protected_process:0;is_protected_process_light:0;image_base:0x00007FF68B130000";
            std::string expect = "{\"type\":\"peb\",\"time\":\"133727882463779926\",\"id\":\"1544\",\"parent_pid\":\"996\",\"image_path\":\"C:\\\\Windows\\\\system32\\\\notepad.exe\",\"commandline\":\"C:\\\\Windows\\\\system32\\\\notepad.exe \",\"working_dir\":\"C:\\\\Users\\\\hacker\\\\\",\"is_debugged\":\"0\",\"is_protected_process\":\"0\",\"is_protected_process_light\":\"0\",\"image_base\":\"0x00007FF68B130000\"}";

            EventProducer eventProducer;
            std::string result = eventProducer.ConvertLogLineToJsonEvent(input);
            Assert::AreEqual(expect.c_str(), result.c_str());
        }

        TEST_METHOD(TestParseEventAsJson)
        {
            std::string eventStr = "{\"type\":\"kernel\",\"time\":\"133727882463689912\",\"callback\":\"create_process\",\"krn_pid\":\"996\",\"pid\":\"1544\",\"name\":\"\\\\Device\\\\HarddiskVolume2\\\\Windows\\\\System32\\\\notepad.exe\"}";
            nlohmann::json j = nlohmann::json::parse(eventStr);

            Assert::AreEqual("kernel", j["type"].get<std::string>().c_str());
            Assert::AreEqual("133727882463689912", j["time"].get<std::string>().c_str());
            Assert::AreEqual("\\Device\\HarddiskVolume2\\Windows\\System32\\notepad.exe", j["name"].get<std::string>().c_str());

            /*
            // Debug:
            try
            {
                nlohmann::json j = nlohmann::json::parse(eventStrUtf8);
            }
            catch (const nlohmann::json::exception& e)
            {
                LOG_A(LOG_INFO, "Exception: %s", e.what());
            }
            */
        }

	};
}
