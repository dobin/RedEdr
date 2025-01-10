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
			Assert::AreEqual(L"--X", getMemoryRegionProtect(0x10));
			Assert::AreEqual(L"RWX", getMemoryRegionProtect(0x40));
			Assert::AreEqual(L"EXECUTE_WRITECOPY", getMemoryRegionProtect(0x80));

			Assert::AreEqual(L"IMAGE", getMemoryRegionType(0x1000000));
			Assert::AreEqual(L"MAPPED", getMemoryRegionType(0x40000));
			Assert::AreEqual(L"PRIVATE", getMemoryRegionType(0x20000));
		}
	};
}
