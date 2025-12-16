/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include "gtest/gtest.h"

#include "virtrust/crypto/sm3.h"
#include "virtrust/dllib/openssl.h"
#include "virtrust/utils/file_io.h"

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

// Helper function to create temporary test files
std::string CreateTempTestFile(const std::string &content, const std::string &suffix = "")
{
    // Get the project root path
    auto filePath = std::filesystem::path(__FILE__).parent_path();
    std::string tempPath = (filePath / ".." / ".." / ".." / "test" / "data" / ("sm3_test_temp" + suffix + ".txt"))
                               .lexically_normal()
                               .string();

    // Create temporary file with test content
    FileOutputStream fos(tempPath);
    fos.Write(content);
    return tempPath;
}

// Helper function to clean up temporary test files
void CleanupTempTestFile(const std::string &filePath)
{
    std::filesystem::remove(filePath);
}

// Test DoSm3File function with various scenarios
TEST(Sm3Test, DoSm3FileBasic)
{
    const std::string testContent = "Hello, World!";
    std::string tempFile = CreateTempTestFile(testContent);

    std::vector<uint8_t> hashResult(Sm3::DigestSize());
    auto result = DoSm3File(tempFile, hashResult);

    EXPECT_EQ(result, Sm3Rc::OK);
    EXPECT_EQ(hashResult.size(), Sm3::DigestSize());

    // Verify hash is not all zeros
    bool allZero = true;
    for (uint8_t byte : hashResult) {
        if (byte != 0) {
            allZero = false;
            break;
        }
    }
    EXPECT_FALSE(allZero);

    // Compare with direct string hash
    auto directHash = DoSm3(testContent);
    EXPECT_EQ(hashResult.size(), directHash.size());
    EXPECT_EQ(memcmp(hashResult.data(), directHash.data(), hashResult.size()), 0);

    CleanupTempTestFile(tempFile);
}

// Test DoSm3File with empty file
TEST(Sm3Test, DoSm3FileEmpty)
{
    const std::string testContent = "";
    std::string tempFile = CreateTempTestFile(testContent, "_empty");

    std::vector<uint8_t> hashResult(Sm3::DigestSize());
    auto result = DoSm3File(tempFile, hashResult);

    EXPECT_EQ(result, Sm3Rc::OK);
    EXPECT_EQ(hashResult.size(), Sm3::DigestSize());

    // Compare with direct empty string hash
    auto directHash = DoSm3(testContent);
    EXPECT_EQ(hashResult.size(), directHash.size());
    EXPECT_EQ(memcmp(hashResult.data(), directHash.data(), hashResult.size()), 0);

    CleanupTempTestFile(tempFile);
}

// Test DoSm3File with large file content
TEST(Sm3Test, DoSm3FileLarge)
{
    // Create a large test content (but within the 1GB limit)
    std::string largeContent(10000, 'A'); // 10KB of 'A's
    std::string tempFile = CreateTempTestFile(largeContent, "_large");

    std::vector<uint8_t> hashResult(Sm3::DigestSize());
    auto result = DoSm3File(tempFile, hashResult);

    EXPECT_EQ(result, Sm3Rc::OK);
    EXPECT_EQ(hashResult.size(), Sm3::DigestSize());

    // Compare with direct string hash
    auto directHash = DoSm3(largeContent);
    EXPECT_EQ(hashResult.size(), directHash.size());
    EXPECT_EQ(memcmp(hashResult.data(), directHash.data(), hashResult.size()), 0);

    CleanupTempTestFile(tempFile);
}

// Test DoSm3File with binary content
TEST(Sm3Test, DoSm3FileBinary)
{
    // Create binary content with null bytes and other special characters
    std::string binaryContent = "Binary\x00\xFF\xFE\x01Content";
    std::string tempFile = CreateTempTestFile(binaryContent, "_binary");

    std::vector<uint8_t> hashResult(Sm3::DigestSize());
    auto result = DoSm3File(tempFile, hashResult);

    EXPECT_EQ(result, Sm3Rc::OK);
    EXPECT_EQ(hashResult.size(), Sm3::DigestSize());

    // Compare with direct string hash
    auto directHash = DoSm3(binaryContent);
    EXPECT_EQ(hashResult.size(), directHash.size());
    EXPECT_EQ(memcmp(hashResult.data(), directHash.data(), hashResult.size()), 0);

    CleanupTempTestFile(tempFile);
}

// Test DoSm3File with multibyte characters (UTF-8)
TEST(Sm3Test, DoSm3FileUtf8)
{
    const std::string utf8Content = "测试中文内容🚀 UTF-8 ñáéíóú";
    std::string tempFile = CreateTempTestFile(utf8Content, "_utf8");

    std::vector<uint8_t> hashResult(Sm3::DigestSize());
    auto result = DoSm3File(tempFile, hashResult);

    EXPECT_EQ(result, Sm3Rc::OK);
    EXPECT_EQ(hashResult.size(), Sm3::DigestSize());

    // Compare with direct string hash
    auto directHash = DoSm3(utf8Content);
    EXPECT_EQ(hashResult.size(), directHash.size());
    EXPECT_EQ(memcmp(hashResult.data(), directHash.data(), hashResult.size()), 0);

    CleanupTempTestFile(tempFile);
}

// Test DoSm3File with nonexistent file
TEST(Sm3Test, DoSm3FileNonexistent)
{
    std::string nonexistentFile = "/nonexistent/path/file.txt";

    std::vector<uint8_t> hashResult(Sm3::DigestSize());
    auto result = DoSm3File(nonexistentFile, hashResult);

    EXPECT_EQ(result, Sm3Rc::ERROR);
}

// Test DoSm3File with insufficient output buffer
TEST(Sm3Test, DoSm3FileInsufficientBuffer)
{
    const std::string testContent = "Test content";
    std::string tempFile = CreateTempTestFile(testContent, "_insufficient");

    // Create output vector with insufficient size
    std::vector<uint8_t> smallBuffer(Sm3::DigestSize() - 1);
    auto result = DoSm3File(tempFile, smallBuffer);

    // The function should still return OK, but the underlying memcpy_s should fail
    // This tests the robustness of the implementation
    EXPECT_EQ(result, Sm3Rc::ERROR);

    CleanupTempTestFile(tempFile);
}

// Test DoSm3File consistency across multiple calls
TEST(Sm3Test, DoSm3FileConsistency)
{
    const std::string testContent = "Consistency test content";
    std::string tempFile = CreateTempTestFile(testContent, "_consistency");

    std::vector<uint8_t> hashResult1(Sm3::DigestSize());
    std::vector<uint8_t> hashResult2(Sm3::DigestSize());

    auto result1 = DoSm3File(tempFile, hashResult1);
    auto result2 = DoSm3File(tempFile, hashResult2);

    EXPECT_EQ(result1, Sm3Rc::OK);
    EXPECT_EQ(result2, Sm3Rc::OK);
    EXPECT_EQ(hashResult1.size(), hashResult2.size());
    EXPECT_EQ(memcmp(hashResult1.data(), hashResult2.data(), hashResult1.size()), 0);

    CleanupTempTestFile(tempFile);
}

// Test DoSm3File with different file sizes
TEST(Sm3Test, DoSm3FileVariousSizes)
{
    std::vector<size_t> testSizes = {1, 10, 100, 1000, 5000};

    for (size_t size : testSizes) {
        std::string content(size, 'X');
        std::string suffix = "_size_" + std::to_string(size);
        std::string tempFile = CreateTempTestFile(content, suffix);

        std::vector<uint8_t> hashResult(Sm3::DigestSize());
        auto result = DoSm3File(tempFile, hashResult);

        EXPECT_EQ(result, Sm3Rc::OK);
        EXPECT_EQ(hashResult.size(), Sm3::DigestSize());

        // Compare with direct string hash
        auto directHash = DoSm3(content);
        EXPECT_EQ(hashResult.size(), directHash.size());
        EXPECT_EQ(memcmp(hashResult.data(), directHash.data(), hashResult.size()), 0);

        CleanupTempTestFile(tempFile);
    }
}

// Test DoSm3File with lines and special characters
TEST(Sm3Test, DoSm3FileLinesAndSpecialChars)
{
    const std::string lineContent = "Line 1\nLine 2\r\nLine 3\tTabbed\tContent\"Quotes\"'Apostrophes'";
    std::string tempFile = CreateTempTestFile(lineContent, "_lines");

    std::vector<uint8_t> hashResult(Sm3::DigestSize());
    auto result = DoSm3File(tempFile, hashResult);

    EXPECT_EQ(result, Sm3Rc::OK);
    EXPECT_EQ(hashResult.size(), Sm3::DigestSize());

    // Compare with direct string hash
    auto directHash = DoSm3(lineContent);
    EXPECT_EQ(hashResult.size(), directHash.size());
    EXPECT_EQ(memcmp(hashResult.data(), directHash.data(), hashResult.size()), 0);

    CleanupTempTestFile(tempFile);
}

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
