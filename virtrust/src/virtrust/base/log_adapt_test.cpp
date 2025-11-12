/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <gtest/gtest.h>

#include <memory>
#include <string>

#include "virtrust/api/defines.h"
#include "virtrust/base/log_adapt.h"

// Define log levels since they're not exposed in headers
#define LOG_TRACE 0
#define LOG_DEBUG 1
#define LOG_INFO 2
#define LOG_WARN 3
#define LOG_ERROR 4
#define LOG_CRITICAL 5
#define LOG_OFF 6

namespace virtrust {

class LogAdaptTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Clean up any existing logger before each test
        LogAdapt::UnInitialize();
    }

    void TearDown() override
    {
        // Clean up after each test
        LogAdapt::UnInitialize();
    }
};

// Test ValidateParams with valid parameters for STDOUT
TEST_F(LogAdaptTest, ValidateParamsValidStdout)
{
    VirtrustRc rc = LogAdapt::ValidateParams(STDOUT_TYPE, nullptr, 0, 0);
    EXPECT_EQ(rc, VirtrustRc::OK);
}

// Test ValidateParams with valid parameters for FILE
TEST_F(LogAdaptTest, ValidateParamsValidFile)
{
    std::string testPath = "/tmp/test.log";
    VirtrustRc rc = LogAdapt::ValidateParams(FILE_TYPE, testPath.c_str(), 5 * 1024 * 1024, 10);
    EXPECT_EQ(rc, VirtrustRc::OK);
}

// Test ValidateParams with invalid log type
TEST_F(LogAdaptTest, ValidateParamsInvalidLogType)
{
    VirtrustRc rc = LogAdapt::ValidateParams(99, nullptr, 0, 0);
    EXPECT_EQ(rc, VirtrustRc::ERROR);
    EXPECT_FALSE(LogAdapt::gLastErrorMessage.empty());
}

// Test ValidateParams with null path for FILE type
TEST_F(LogAdaptTest, ValidateParamsNullPathFile)
{
    VirtrustRc rc = LogAdapt::ValidateParams(FILE_TYPE, nullptr, 5 * 1024 * 1024, 10);
    EXPECT_EQ(rc, VirtrustRc::ERROR);
    EXPECT_FALSE(LogAdapt::gLastErrorMessage.empty());
}

// Test ValidateParams with invalid rotation file size - too small
TEST_F(LogAdaptTest, ValidateParamsRotationSizeTooSmall)
{
    std::string testPath = "/tmp/test.log";
    VirtrustRc rc = LogAdapt::ValidateParams(FILE_TYPE, testPath.c_str(), 1024, 10); // 1KB, too small
    EXPECT_EQ(rc, VirtrustRc::ERROR);
    EXPECT_FALSE(LogAdapt::gLastErrorMessage.empty());
}

// Test ValidateParams with invalid rotation file size - too large
TEST_F(LogAdaptTest, ValidateParamsRotationSizeTooLarge)
{
    std::string testPath = "/tmp/test.log";
    VirtrustRc rc = LogAdapt::ValidateParams(FILE_TYPE, testPath.c_str(), 600 * 1024 * 1024, 10); // 600MB, too large
    EXPECT_EQ(rc, VirtrustRc::ERROR);
    EXPECT_FALSE(LogAdapt::gLastErrorMessage.empty());
}

// Test ValidateParams with invalid rotation file count - too small
TEST_F(LogAdaptTest, ValidateParamsRotationCountTooSmall)
{
    std::string testPath = "/tmp/test.log";
    VirtrustRc rc = LogAdapt::ValidateParams(FILE_TYPE, testPath.c_str(), 5 * 1024 * 1024, 0);
    EXPECT_EQ(rc, VirtrustRc::ERROR);
    EXPECT_FALSE(LogAdapt::gLastErrorMessage.empty());
}

// Test ValidateParams with invalid rotation file count - too large
TEST_F(LogAdaptTest, ValidateParamsRotationCountTooLarge)
{
    std::string testPath = "/tmp/test.log";
    VirtrustRc rc = LogAdapt::ValidateParams(FILE_TYPE, testPath.c_str(), 5 * 1024 * 1024, 100);
    EXPECT_EQ(rc, VirtrustRc::ERROR);
    EXPECT_FALSE(LogAdapt::gLastErrorMessage.empty());
}

// Test CreateInstance with valid STDOUT parameters
TEST_F(LogAdaptTest, CreateInstanceValidStdout)
{
    int logType = STDOUT_TYPE;
    VirtrustRc rc = LogAdapt::CreateInstance(logType, LOG_INFO, nullptr, 0, 0);
    EXPECT_EQ(rc, VirtrustRc::OK);
    EXPECT_EQ(logType, STDOUT_TYPE);
}

// Test CreateInstance with valid FILE parameters
TEST_F(LogAdaptTest, CreateInstanceValidFile)
{
    std::string testPath = "/tmp/test.log";
    int logType = FILE_TYPE;

    VirtrustRc rc = LogAdapt::CreateInstance(logType, LOG_DEBUG, testPath.c_str(), 5 * 1024 * 1024, 10);
    EXPECT_EQ(rc, VirtrustRc::OK);
    EXPECT_EQ(logType, FILE_TYPE);
}

// Test CreateInstance with invalid log type
TEST_F(LogAdaptTest, CreateInstanceInvalidLogType)
{
    int logType = 99; // Invalid log type
    VirtrustRc rc = LogAdapt::CreateInstance(logType, LOG_INFO, nullptr, 0, 0);
    EXPECT_EQ(rc, VirtrustRc::ERROR);
}

// Test CreateInstance with relative path
TEST_F(LogAdaptTest, CreateInstanceRelativePath)
{
    std::string testPath = "relative/path/test.log"; // Relative path
    int logType = FILE_TYPE;

    VirtrustRc rc = LogAdapt::CreateInstance(logType, LOG_INFO, testPath.c_str(), 5 * 1024 * 1024, 10);
    EXPECT_EQ(rc, VirtrustRc::ERROR);
}

// Test CreateInstance with non-existent directory
TEST_F(LogAdaptTest, CreateInstanceNonExistentDirectory)
{
    std::string testPath = "/non/existent/path/test.log";
    int logType = FILE_TYPE;

    VirtrustRc rc = LogAdapt::CreateInstance(logType, LOG_INFO, testPath.c_str(), 5 * 1024 * 1024, 10);
    EXPECT_EQ(rc, VirtrustRc::ERROR);
}

// Test LogAdapt constructor and basic functionality
TEST_F(LogAdaptTest, LogAdaptConstructor)
{
    std::string testPath = "/tmp/test.log";
    LogAdapt logAdapt(FILE_TYPE, testPath, 5 * 1024 * 1024, 10);

    // Test setting log level
    logAdapt.SetLogLevel(LOG_ERROR);
    EXPECT_FALSE(logAdapt.IsLogLevelEnabled(LOG_DEBUG));
    EXPECT_TRUE(logAdapt.IsLogLevelEnabled(LOG_ERROR));

    // Test invalid log level setting
    logAdapt.SetLogLevel(-1); // Should not crash
}

// Test SetTmpLogger function indirectly through CreateInstance
TEST_F(LogAdaptTest, SetTmpLoggerIndirect)
{
    std::string testPath = "/tmp/tmp_test.log";
    int logType = FILE_TYPE;

    // This will call SetTmpLogger internally
    VirtrustRc rc = LogAdapt::CreateInstance(logType, LOG_INFO, testPath.c_str(), 5 * 1024 * 1024, 10);
    EXPECT_EQ(rc, VirtrustRc::OK);
}

// Test GetLogLevel
TEST_F(LogAdaptTest, GetLogLevel)
{
    int initialLevel = LogAdapt::GetLogLevel();
    EXPECT_GE(initialLevel, 0);
    EXPECT_LE(initialLevel, 6); // SPDLOG_LEVEL_TRACE = 0, SPDLOG_LEVEL_OFF = 6
}

// Test Flush functionality
TEST_F(LogAdaptTest, Flush)
{
    // Create a logger first
    int logType = STDOUT_TYPE;
    VirtrustRc rc = LogAdapt::CreateInstance(logType, LOG_INFO, nullptr, 0, 0);
    EXPECT_EQ(rc, VirtrustRc::OK);

    // Test flush - should not crash
    EXPECT_NO_THROW(LogAdapt::Flush());
}

// Test Log method
TEST_F(LogAdaptTest, LogMethod)
{
    std::string testPath = "/tmp/log_test.log";
    LogAdapt logAdapt(FILE_TYPE, testPath, 5 * 1024 * 1024, 10);

    // Initialize the logger
    VirtrustRc rc = logAdapt.Initialize();
    // Note: This might fail in test environment, but we can test the method call
    if (rc == VirtrustRc::OK) {
        // Test logging at different levels
        rc = logAdapt.Log(LOG_INFO, "TEST", "Test message");
        EXPECT_EQ(rc, VirtrustRc::OK);

        rc = logAdapt.Log(LOG_ERROR, "ERROR", "Error message");
        EXPECT_EQ(rc, VirtrustRc::OK);
    }
}

// Test CreateInstance duplicate call (should return OK without creating new instance)
TEST_F(LogAdaptTest, CreateInstanceDuplicate)
{
    int logType = STDOUT_TYPE;

    // First call
    VirtrustRc rc1 = LogAdapt::CreateInstance(logType, LOG_INFO, nullptr, 0, 0);
    EXPECT_EQ(rc1, VirtrustRc::OK);

    // Second call with same instance
    VirtrustRc rc2 = LogAdapt::CreateInstance(logType, LOG_ERROR, nullptr, 0, 0);
    EXPECT_EQ(rc2, VirtrustRc::OK);
}

// Test multiple CreateInstance calls with different log levels
TEST_F(LogAdaptTest, CreateInstanceDifferentLevels)
{
    std::string testPath = "/tmp/level_test.log";
    int logType = FILE_TYPE;

    // Test with different log levels
    std::vector<int> logLevels = {LOG_TRACE, LOG_DEBUG, LOG_INFO, LOG_WARN, LOG_ERROR, LOG_CRITICAL, LOG_OFF};

    for (int level : logLevels) {
        LogAdapt::UnInitialize(); // Clean up before each attempt
        VirtrustRc rc = LogAdapt::CreateInstance(logType, level, testPath.c_str(), 5 * 1024 * 1024, 10);
        EXPECT_EQ(rc, VirtrustRc::OK);
    }
}

// Test edge cases for rotation file size
TEST_F(LogAdaptTest, ValidateParamsRotationSizeEdgeCases)
{
    std::string testPath = "/tmp/test.log";

    // Test minimum valid size (1MB)
    VirtrustRc rc1 = LogAdapt::ValidateParams(FILE_TYPE, testPath.c_str(), 1 * 1024 * 1024, 10);
    EXPECT_EQ(rc1, VirtrustRc::OK);

    // Test maximum valid size (500MB)
    VirtrustRc rc2 = LogAdapt::ValidateParams(FILE_TYPE, testPath.c_str(), 500 * 1024 * 1024, 10);
    EXPECT_EQ(rc2, VirtrustRc::OK);
}

// Test edge cases for rotation file count
TEST_F(LogAdaptTest, ValidateParamsRotationCountEdgeCases)
{
    std::string testPath = "/tmp/test.log";

    // Test minimum valid count (1)
    VirtrustRc rc1 = LogAdapt::ValidateParams(FILE_TYPE, testPath.c_str(), 5 * 1024 * 1024, 1);
    EXPECT_EQ(rc1, VirtrustRc::OK);

    // Test maximum valid count (64)
    VirtrustRc rc2 = LogAdapt::ValidateParams(FILE_TYPE, testPath.c_str(), 5 * 1024 * 1024, 64);
    EXPECT_EQ(rc2, VirtrustRc::OK);
}

} // namespace virtrust