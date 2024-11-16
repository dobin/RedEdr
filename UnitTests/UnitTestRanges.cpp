#include "CppUnitTest.h"

#include "logging.h"
#include "ranges.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace RangeSetTests
{
    TEST_CLASS(RangeSetTests)
    {
    public:
        TEST_METHOD(SimpleTest)
        {
            RangeSet rangeSet;
            rangeSet.add(Range(1, 5, NULL));
            rangeSet.add(Range(10, 15, NULL));
            Assert::IsTrue(rangeSet.contains(2));
            Assert::IsFalse(rangeSet.contains(1337));
        }

        /*
        TEST_METHOD(TestAddAndMergeOverlappingRanges)
        {
            RangeSet rangeSet;
            rangeSet.add(Range(1, 5, NULL));
            rangeSet.add(Range(10, 15, NULL));
            rangeSet.add(Range(3, 12, NULL));  // This should merge with the previous ranges

            std::ostringstream oss;
            for (const auto& range : rangeSet.ranges_) {
                oss << "[" << range.start_ << ", " << range.end_ << ") ";
            }
            std::string expectedOutput = "[1, 15) ";
            Assert::AreEqual(expectedOutput, oss.str(), L"Expected merged range to be [1, 15)");
        }
        */

        TEST_METHOD(TestContains)
        {
            RangeSet rangeSet;
            rangeSet.add(Range(1, 5, (void*)0xA0));
            rangeSet.add(Range(10, 15, (void*) 0xB0));

            Assert::IsTrue(rangeSet.contains(4), L"Expected rangeSet to contain 4");
            Assert::IsTrue(rangeSet.contains(12), L"Expected rangeSet to contain 12");
            Assert::IsFalse(rangeSet.contains(8), L"Expected rangeSet not to contain 8");
            Assert::IsFalse(rangeSet.contains(16), L"Expected rangeSet not to contain 16");

			//Assert::AreEqual((void*)0xA0, rangeSet.get(4).data_, L"Expected data to be 0xA0");
        }

        TEST_METHOD(TestIntersection)
        {
            RangeSet rangeSet;
            rangeSet.add(Range(1, 5, NULL));
            rangeSet.add(Range(10, 15, NULL));
            rangeSet.add(Range(3, 12, NULL));  // This should merge to [1, 15)

            RangeSet otherSet;
            otherSet.add(Range(0, 3, NULL));
            otherSet.add(Range(10, 13, NULL));

            RangeSet intersection = rangeSet.intersect(otherSet);

            std::ostringstream oss;
            for (const auto& range : intersection.ranges_) {
                oss << "[" << range.start_ << ", " << range.end_ << ") ";
            }
            //std::string expectedOutput = "[1, 3) [10, 13) ";
            //Assert::AreEqual(expectedOutput, oss.str(), L"Expected intersection result to be [1, 3) [10, 13)");
        }
    };
}

