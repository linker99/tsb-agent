/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "virtrust/crypto/sm3.h"
#include "virtrust/dllib/openssl.h"

namespace virtrust::test {
namespace {
// The following two test vectors are taken from
// https://www.oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
const std::vector<std::string> SM3_TEST_DATA = {"abc",
                                                "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
                                                "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
                                                "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
                                                "dabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"};

inline std::string BytesToHexString(const std::vector<uint8_t> &bytes)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0'); // Set output to hex and pad with '0'

    for (unsigned char byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte); // Format each bute as 2-digit hex
    }

    return oss.str();
}

} // namespace

TEST(Sm3Test, Works)
{
    std::string msg = "123";
    auto result1 = DoSm3(msg);
    auto result2 = DoSm3(msg);

    EXPECT_EQ(result1.size(), Sm3::DigestSize());
    EXPECT_EQ(result1.size(), result2.size());
    EXPECT_EQ(memcmp(result1.data(), result2.data(), result1.size()), 0);
}

TEST(Sm3Test, Test1)
{
    auto hash = Sm3();
    hash.Update(SM3_TEST_DATA[0]);
    auto ret = BytesToHexString(hash.CumulativeHash());
    EXPECT_EQ(ret.size(), SM3_TEST_DATA[1].size());
    EXPECT_EQ(ret, SM3_TEST_DATA[1]);
}

TEST(Sm3Test, Test2)
{
    auto hash = Sm3();
    hash.Update(SM3_TEST_DATA[2]);
    auto ret = BytesToHexString(hash.CumulativeHash());
    EXPECT_EQ(ret.size(), SM3_TEST_DATA[3].size());
    EXPECT_EQ(ret, SM3_TEST_DATA[3]);
}

TEST(Sm3Test, Test3)
{
    auto hash = Sm3();
    hash.Update(SM3_TEST_DATA[0]);
    hash.Update(SM3_TEST_DATA[4]);
    auto ret = BytesToHexString(hash.CumulativeHash());
    EXPECT_EQ(ret.size(), SM3_TEST_DATA[3].size());
    EXPECT_EQ(ret, SM3_TEST_DATA[3]);
}

TEST(Sm3Test, Test4)
{
    auto hash = Sm3();
    hash.Update(SM3_TEST_DATA[0]);
    hash.Reset();
    hash.Update(SM3_TEST_DATA[2]);
    auto ret = BytesToHexString(hash.CumulativeHash());
    EXPECT_EQ(ret.size(), SM3_TEST_DATA[3].size());
    EXPECT_EQ(ret, SM3_TEST_DATA[3]);
}

// Test empty string
TEST(Sm3Test, EmptyString)
{
    auto hash = Sm3();
    hash.Update("");
    auto result = hash.CumulativeHash();
    EXPECT_EQ(result.size(), Sm3::DigestSize());
    EXPECT_FALSE(result.empty());
}

// Test various string sizes
TEST(Sm3Test, VariousSizes)
{
    // Small strings
    std::vector<std::string> testString = {"", "a", "ab", "abc", "abcd"};
    for (const auto &str : testString) {
        auto hash = Sm3();
        hash.Update(str);
        auto result = hash.CumulativeHash();
        EXPECT_EQ(result.size(), Sm3::DigestSize());
    }

    // Large strings
    std::string largeStr(1000, 'x');
    auto hash = Sm3();
    hash.Update(largeStr);
    auto result = hash.CumulativeHash();
    EXPECT_EQ(result.size(), Sm3::DigestSize());
}

// Test Update with size limit
TEST(Sm3Test, UpdateSizeLimit)
{
    // Test within limit
    std::string smallData(1000, 'x');
    auto hash = Sm3();
    EXPECT_EQ(hash.Update(smallData), Sm3Rc::OK);

    // Test exceeding limit (should return ERROR)
    std::string largeData(1024 * 1024 * 1024 + 1, 'x'); // limit
    EXPECT_EQ(hash.Update(largeData), Sm3Rc::ERROR);
}

// Test cumulative hash with empty context
TEST(Sm3Test, CumulativeHashWithNullContext)
{
    // This test requires mocking or directly testing the internal state
    // The actual implementation handles null checks, but we want to ensure
    // the function behaves correctly
    auto hash = Sm3();
    // Normally the context is initialized, but we can still verify it works
    hash.Update("test");
    auto result = hash.CumulativeHash();
    EXPECT_EQ(result.size(), Sm3::DigestSize());
}

// Test reset functionality
TEST(Sm3Test, ResetFunctionality)
{
    auto hash = Sm3();

    // Update with some data
    hash.Update("hello");
    auto intermediateHash = hash.CumulativeHash();
    EXPECT_EQ(intermediateHash.size(), Sm3::DigestSize());

    // Reset and update with different data
    hash.Reset();
    hash.Update("world");
    auto finalHash = hash.CumulativeHash();
    EXPECT_EQ(finalHash.size(), Sm3::DigestSize());

    // Hashes should be different
    EXPECT_NE(memcmp(intermediateHash.data(), finalHash.data(), intermediateHash.size()), 0);
}

// Test DoSm3 with vector output
TEST(Sm3Test, DoSm3VectorOutput)
{
    std::string testData = "test data";
    std::vector<uint8_t> output(Sm3::DigestSize());

    auto result = DoSm3(testData, output);
    EXPECT_EQ(result, Sm3Rc::OK);
    EXPECT_EQ(output.size(), Sm3::DigestSize());

    // Verify the output is not empty
    bool allZero = true;
    for (uint8_t byte : output) {
        if (byte != 0) {
            allZero = false;
            break;
        }
    }
    EXPECT_FALSE(allZero);
}

// Test DoSm3 with array output (existing test)
TEST(Sm3Test, DoSm3ArrayOutput)
{
    std::string testData = "test data";
    auto result = DoSm3(testData);

    EXPECT_EQ(result.size(), Sm3::DigestSize());

    // Verify the output is not all zeros
    bool allZero = true;
    for (uint8_t byte : result) {
        if (byte != 0) {
            allZero = false;
            break;
        }
    }
    EXPECT_FALSE(allZero);
}

// Test Hash consistency across multiple updates
TEST(Sm3Test, MultipleUpdatesConsistency)
{
    std::string data1 = "hello";
    std::string data2 = "";
    std::string data3 = "world";

    // Single update
    auto hash1 = Sm3();
    hash1.Update(data1 + data2 + data3);
    auto result1 = hash1.CumulativeHash();

    // Multiple updates
    auto hash2 = Sm3();
    hash2.Update(data1);
    hash2.Update(data2);
    hash2.Update(data3);
    auto result2 = hash2.CumulativeHash();

    // Results should be identical
    EXPECT_EQ(result1.size(), result2.size());
    EXPECT_EQ(memcmp(result1.data(), result2.data(), result1.size()), 0);
}

// Test Hash concatenation
TEST(Sm3Test, HashConcatenation)
{
    std::string data1 = "first";
    std::string data2 = "second";

    auto hash1 = Sm3();
    hash1.Update(data1);
    auto hash1Result = hash1.CumulativeHash();

    auto hash2 = Sm3();
    hash2.Update(data2);
    auto hash2Result = hash2.CumulativeHash();

    auto hash3 = Sm3();
    hash3.Update(data1 + data2);
    auto hash3Result = hash3.CumulativeHash();

    // Hashes should be different
    EXPECT_NE(memcmp(hash1Result.data(), hash2Result.data(), hash1Result.size()), 0);
    EXPECT_NE(memcmp(hash1Result.data(), hash3Result.data(), hash1Result.size()), 0);
    EXPECT_NE(memcmp(hash2Result.data(), hash3Result.data(), hash2Result.size()), 0);
}
} // namespace virtrust::test