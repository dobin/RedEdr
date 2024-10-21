//#include "pch.h"
#include "CppUnitTest.h"

#include "analyzer.h"
#include "utils.h"
#include "json.hpp"
#include "logging.h"


using namespace Microsoft::VisualStudio::CppUnitTestFramework;


namespace UnitTests
{
    TEST_CLASS(Analyzer)
    {
    public:
        TEST_METHOD(Test1)
        {
            std::string line = "{\"type\":\"dll\",\"time\":\"133738319156815383\",\"pid\":\"16908\",\"tid\":\"15656\",\"func\":\"ProtectVirtualMemory\",\"pid\":\"FFFFFFFFFFFFFFFF\",\"base_addr\":\"000001686111FCF8\",\"size\":\"1696\",\"protect\":\"0x40\",\"protect_str\":\"RWX\",\"callstack\":[{\"idx\":\"0\",\"addr\":\"00007FFBC8FEBB8A\",\"page_addr\":\"00007FFBC8FEB000\",\"size\":\"135168\",\"state\":\"0x1000\",\"protect\":\"0x40\",\"type\":\"0x1000000\"},{\"idx\":\"1\",\"addr\":\"00007FFBC8FEC7F4\",\"page_addr\":\"00007FFBC8FEC000\",\"size\":\"131072\",\"state\":\"0x1000\",\"protect\":\"0x20\",\"type\":\"0x40000\"},{\"idx\":\"2\",\"addr\":\"00007FFBDEC44518\",\"page_addr\":\"00007FFBDEC44000\",\"size\":\"823296\",\"state\":\"0x1000\",\"protect\":\"0x20\",\"type\":\"0x1000000\"},{\"idx\":\"3\",\"addr\":\"00007FFBDEC2288A\",\"page_addr\":\"00007FFBDEC22000\",\"size\":\"962560\",\"state\":\"0x1000\",\"protect\":\"0x20\",\"type\":\"0x1000000\"},{\"idx\":\"4\",\"addr\":\"00007FFBDEC50128\",\"page_addr\":\"00007FFBDEC50000\",\"size\":\"774144\",\"state\":\"0x1000\",\"protect\":\"0x20\",\"type\":\"0x1000000\"},{\"idx\":\"5\",\"addr\":\"00007FFBDEC500D3\",\"page_addr\":\"00007FFBDEC50000\",\"size\":\"774144\",\"state\":\"0x1000\",\"protect\":\"0x20\",\"type\":\"0x1000000\"}]}";
            AnalyzeEvent(line);
        }

    };
}
