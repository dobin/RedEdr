//#include "pch.h"
#include "CppUnitTest.h"

#include "output.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace UnitTests
{
	TEST_CLASS(Output)
	{
	public:

		TEST_METHOD(TestConvertLineToJson)
		{
            std::wstring input = L"type:dll;time:133723719791285666;krn_pid:14496;func:NtOpenThread;"
                "thread_handle:0x000000642EB7F1D8;access_mask:0x5a;client_id_process:0x0000000000000000;"
                "client_id_thread:0x0000000000004ED0;callstack:[{idx:0;addr:00007FF9590993A2;page_addr:00007FF959099000;"
                "size:69632;state:0x1000;protect:0x20;type:0x1000000},{idx:1;addr:000000642EB7CC6E;page_addr:000000642EB7C000;"
                "size:16384;state:0x1000;protect:0x4;type:0x20000},{idx:2;addr:0000000000000800;page_addr:0000000000000000;"
                "size:224591872;state:0x10000;protect:0x1;type:0x0},{idx:3;addr:00007FF9590ABE80;page_addr:00007FF9590AB000;"
                "size:36864;state:0x1000;protect:0x2;type:0x1000000},{idx:4;addr:0000000000000003;page_addr:0000000000000000;"
                "size:224591872;state:0x10000;protect:0x1;type:0x0},{idx:5;addr:000000642EB7BFE0;page_addr:000000642EB7B000;"
                "size:20480;state:0x1000;protect:0x4;type:0x20000},]";
            std::wstring expect = L"{\"type\":\"dll\",\"time\":\"133723719791285666\",\"krn_pid\":\"14496\",\"func\":\"NtOpenThread\",\"thread_handle\":\"0x000000642EB7F1D8\",\"access_mask\":\"0x5a\",\"client_id_process\":\"0x0000000000000000\",\"client_id_thread\":\"0x0000000000004ED0\",\"callstack\":[{\"idx\":\"0\",\"addr\":\"00007FF9590993A2\",\"page_addr\":\"00007FF959099000\",\"size\":\"69632\",\"state\":\"0x1000\",\"protect\":\"0x20\",\"type\":\"0x1000000\"},{\"idx\":\"1\",\"addr\":\"000000642EB7CC6E\",\"page_addr\":\"000000642EB7C000\",\"size\":\"16384\",\"state\":\"0x1000\",\"protect\":\"0x4\",\"type\":\"0x20000\"},{\"idx\":\"2\",\"addr\":\"0000000000000800\",\"page_addr\":\"0000000000000000\",\"size\":\"224591872\",\"state\":\"0x10000\",\"protect\":\"0x1\",\"type\":\"0x0\"},{\"idx\":\"3\",\"addr\":\"00007FF9590ABE80\",\"page_addr\":\"00007FF9590AB000\",\"size\":\"36864\",\"state\":\"0x1000\",\"protect\":\"0x2\",\"type\":\"0x1000000\"},{\"idx\":\"4\",\"addr\":\"0000000000000003\",\"page_addr\":\"0000000000000000\",\"size\":\"224591872\",\"state\":\"0x10000\",\"protect\":\"0x1\",\"type\":\"0x0\"},{\"idx\":\"5\",\"addr\":\"000000642EB7BFE0\",\"page_addr\":\"000000642EB7B000\",\"size\":\"20480\",\"state\":\"0x1000\",\"protect\":\"0x4\",\"type\":\"0x20000\"}]}";
            std::wstring result = ConvertLineToJson(input);
            Assert::AreEqual(expect.c_str(), result.c_str());
		}
	};
}
