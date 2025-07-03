#include "CppUnitTest.h"

#include "utils.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTests
{
	TEST_CLASS(UnitTests)
	{
	public:
		TEST_METHOD(TestStrA) {
			std::string str = "Hello";
			wchar_t* wstr = string2wcharAlloc(str);
			Assert::AreEqual(L"Hello", wstr);
		}

		
		TEST_METHOD(TestTranslate)
		{
			Assert::AreEqual("--X", getMemoryRegionProtect(0x10));
			Assert::AreEqual("RWX", getMemoryRegionProtect(0x40));
			Assert::AreEqual("EXECUTE_WRITECOPY", getMemoryRegionProtect(0x80));

			Assert::AreEqual("IMAGE", getMemoryRegionType(0x1000000));
			Assert::AreEqual("MAPPED", getMemoryRegionType(0x40000));
			Assert::AreEqual("PRIVATE", getMemoryRegionType(0x20000));
		}
	};
}
