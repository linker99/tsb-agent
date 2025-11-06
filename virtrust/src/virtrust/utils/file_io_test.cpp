/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <filesystem>
#include <fstream>
#include <sstream>

#include "gtest/gtest.h"

#include "virtrust/base/logger.h"
#include "virtrust/utils/file_io.h"

namespace virtrust {

namespace {
constexpr size_t MAX_BYTES_LENGTH = 64;
constexpr std::string_view TEST_FILE_CONTENT = "this is a test file.\n";
constexpr std::string_view TEST_FILE_CONTENT_LONG = "this is a test file.\nwith multiple lines\nand more content.\n";

std::string GetTestFilePath()
{
    // Get the project root path (Which is the directory)
    auto filePath = std::filesystem::path(__FILE__);
    return (filePath / ".." / ".." / ".." / ".." / "test" / "data" / "test.txt").lexically_normal().string();
}

std::string GetTempFilePath(const std::string &suffix = "")
{
    // Get the project root path (Which is the directory)
    auto filePath = std::filesystem::path(__FILE__);
    return (filePath / ".." / ".." / ".." / ".." / "test" / "data" / ("temp_file" + suffix + ".txt"))
        .lexically_normal()
        .string();
}

} // namespace

TEST(FileIO, Works)
{
    std::string path(GetTestFilePath());
    FileInputStream fis = FileInputStream(path);
    std::string content = fis.ReadAll();
    ASSERT_EQ(content, TEST_FILE_CONTENT);
}

TEST(FileIO, ReadAll)
{
    std::string path(GetTestFilePath());
    FileInputStream fis = FileInputStream(path);
    std::string content = fis.ReadAll();
    ASSERT_EQ(content, TEST_FILE_CONTENT);
}

TEST(FileIO, GetLength)
{
    std::string path(GetTestFilePath());
    FileInputStream fis = FileInputStream(path);
    size_t length = fis.GetLength();
    ASSERT_EQ(length, TEST_FILE_CONTENT.length());
}

TEST(FileIO, GetName)
{
    std::string path(GetTestFilePath());
    FileInputStream fis = FileInputStream(path);
    const std::string &name = fis.GetName();
    ASSERT_EQ(name, path);
}

TEST(FileIO, Eof)
{
    std::string path(GetTestFilePath());
    FileInputStream fis = FileInputStream(path);

    // Initially not at EOF
    ASSERT_FALSE(fis.Eof());

    // Read all content
    // NOTE EOF/FAIL bit get cleared inside this function
    std::string content = fis.ReadAll();
    EXPECT_FALSE(content.empty());
}

TEST(FileIO, SeekgAndTellg)
{
    std::string path(GetTestFilePath());
    FileInputStream fis = FileInputStream(path);

    // Get initial position
    size_t initialPos = fis.Tellg();
    ASSERT_EQ(initialPos, static_cast<size_t>(0));

    // Read part of the file
    std::string content;
    fis.GetLine(&content, '\n');

    // Get current position
    size_t currentPos = fis.Tellg();
    ASSERT_GT(currentPos, initialPos);

    // Seek back to beginning
    fis.Seekg(0);
    size_t newPos = fis.Tellg();
    ASSERT_EQ(newPos, static_cast<size_t>(0));
}

TEST(FileIO, TransferTo)
{
    std::string path(GetTestFilePath());
    FileInputStream fis = FileInputStream(path);

    std::ostringstream oss;
    fis.TransferTo(oss);

    ASSERT_EQ(oss.str(), TEST_FILE_CONTENT);
}

TEST(FileIO, GetLine)
{
    std::string path(GetTestFilePath());
    FileInputStream fis = FileInputStream(path);

    std::string line;
    fis.GetLine(&line, '\n');

    ASSERT_EQ(line, "this is a test file.");
}

TEST(FileIO, Spawn)
{
    std::string path(GetTestFilePath());
    FileInputStream fis = FileInputStream(path);

    // Save current position
    size_t originalPos = fis.Tellg();

    // Spawn a new stream from current position
    auto spawnedStream = fis.Spawn();

    // Both streams should be at same position
    ASSERT_EQ(spawnedStream->Tellg(), originalPos);

    // Original stream should still work
    std::string line;
    fis.GetLine(&line, '\n');
    EXPECT_EQ(line, "this is a test file.");
}

TEST(FileIO, FileStreamOperators)
{
    std::string path(GetTestFilePath());
    FileInputStream fis = FileInputStream(path);

    // Test boolean conversion operators
    ASSERT_TRUE(static_cast<bool>(fis));
    ASSERT_FALSE(!fis);

    // Test with invalid file (should throw)
    try {
        FileInputStream invalidFis("nonexistent_file.txt");
        FAIL() << "Should have thrown exception";
    } catch (...) {
        // Excepted
    }
}

TEST(FileIO, FileInputStreamRead)
{
    std::string path(GetTestFilePath());
    FileInputStream fis = FileInputStream(path);
    size_t length = TEST_FILE_CONTENT.size();
    // Test Read method with buffer
    char buffer[MAX_BYTES_LENGTH];
    fis.Read(buffer, length);

    std::string content(buffer, length);
    ASSERT_EQ(content, TEST_FILE_CONTENT);
    fis.Close();
}

TEST(FileIO, FileOutputStreamConstructAndDestroy)
{
    std::string tempPath = GetTempFilePath("_construct");

    // Test construction with trunc=true (default)
    {
        FileOutputStream fos(tempPath, true);
        ASSERT_EQ(fos.GetName(), tempPath);
    }

    // Verify file was created
    std::ifstream testFile(tempPath);
    ASSERT_TRUE(testFile.good());
    testFile.close();

    // Test construction with trunc=false (append mode)
    {
        FileOutputStream fos(tempPath, false);
        ASSERT_EQ(fos.GetName(), tempPath);
    }

    // Clean up
    std::filesystem::remove(tempPath);
}

TEST(FileIO, FileOutputStreamWrite)
{
    std::string tempPath = GetTempFilePath("_write");

    {
        FileOutputStream fos(tempPath);

        // Test Write with buffer
        const char *testData = "Hello World!";
        fos.Write(testData, strlen(testData));

        // Test Write with string_view
        std::string_view testStr = "Test string";
        fos.Write(testStr);

        // Test Write with string
        std::string testStr2 = "Another test";
        fos.Write(testStr2.data(), testStr2.size());
    }

    // Verify content was written
    std::ifstream testFile(tempPath);
    std::ostringstream oss;
    oss << testFile.rdbuf();
    std::string content = oss.str();

    ASSERT_NE(content.find("Hello World!"), std::string::npos);
    ASSERT_NE(content.find("Test string"), std::string::npos);
    ASSERT_NE(content.find("Another test"), std::string::npos);

    testFile.close();
    std::filesystem::remove(tempPath);
}

TEST(FileIO, FileOutputStreamTellpAndFlush)
{
    std::string tempPath = GetTempFilePath("_tellp");

    {
        FileOutputStream fos(tempPath);

        // Initial position should be 0
        size_t initialPos = fos.Tellp();
        ASSERT_EQ(initialPos, static_cast<size_t>(0));

        // Write some data
        const char *testData = "Test data";
        fos.Write(testData, strlen(testData));

        // Position should be advanced
        size_t afterWritePos = fos.Tellp();
        ASSERT_EQ(afterWritePos, strlen(testData));

        // Test flush
        fos.Flush();
    }

    // Verify content was written
    std::ifstream testFile(tempPath);
    std::ostringstream oss;
    oss << testFile.rdbuf();
    std::string content = oss.str();

    ASSERT_EQ(content, "Test data");

    testFile.close();
    std::filesystem::remove(tempPath);
}

TEST(FileIO, FileOutputStreamClose)
{
    std::string tempPath = GetTempFilePath("_close");

    {
        FileOutputStream fos(tempPath);
        const char *testData = "Test data";
        fos.Write(testData, strlen(testData));
    }

    // File should be closed and accessible
    std::ifstream testFile(tempPath);
    ASSERT_TRUE(testFile.good());

    std::string content((std::istreambuf_iterator<char>(testFile)), std::istreambuf_iterator<char>());

    ASSERT_EQ(content, "Test data");

    testFile.close();
    std::filesystem::remove(tempPath);
}

TEST(FileIO, FileOutputStreamIsStreaming)
{
    ASSERT_FALSE(FileOutputStream::IsStreaming());
}
} // namespace virtrust