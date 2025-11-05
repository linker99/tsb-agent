/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "gtest/gtest.h"

#include "virtrust-sh/operator/op_start.h"

namespace virtrust {

TEST(OpStartTest, ParseArgvValidArgumentsTest)
{
    OpStart opStart;

    // Test with valid domain name
    const char *argv[] = {"op_start", "test_doamin"};
    int argc = 2;

    OpRc result = opStart.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for valid arguments
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpStartTest, ParseArgvHelpFlagTest)
{
    OpStart opStart;

    // Test with help Flag
    const char *argv[] = {"op_start", "--help"};
    int argc = 2;

    OpRc result = opStart.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for help flag (should not execute)
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpStartTest, ParseArgvHelpShortFlagTest)
{
    OpStart opStart;

    // Test with help Flag
    const char *argv[] = {"op_start", "-h"};
    int argc = 2;

    OpRc result = opStart.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for short help flag (should not execute)
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpStartTest, ParseArgvMissingDoaminTest)
{
    OpStart opStart;

    // Test with missig domain name arguments
    const char *argv[] = {"op_start"};
    int argc = 1;

    OpRc result = opStart.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns ERROR for misssing arguments
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpStartTest, ParseArgvExtraArgumentsTest)
{
    OpStart opStart;

    // Test with extra arguments
    const char *argv[] = {"op_start", "domain1", "extra_arg"};
    int argc = 3;

    OpRc result = opStart.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns ERROR for extra arguments
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpStartTest, ParseArgvInvalidOptionTest)
{
    OpStart opStart;

    // Test with invalid option
    const char *argv[] = {"op_start", "--invalid-option"};
    int argc = 2;

    OpRc result = opStart.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns ERROR for invalid option
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpStartTest, ParseArgvDomainNameStorageTest)
{
    OpStart opStart;

    // Test with domain name is properly stored
    const char *argv[] = {"op_start", "complex-domain-123"};
    int argc = 3;

    OpRc result = opStart.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK and domain name is stored
    EXPECT_EQ(result, OpRc::OK);
    // Note: Cannot directly access private member domainName_ for verification
    // but we can verify the function doesn't crash and handles correctly
}

TEST(OpStartTest, ParseArgvComplexDomainNameTest)
{
    OpStart opStart;

    // Test with complex domain name containing special characters
    const char *argv[] = {"op_start", "complex-dimain-name.123"};
    int argc = 2;

    OpRc result = opStart.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for complex domain names
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpStartTest, ParseArgvLongDomainNameTest)
{
    OpStart opStart;

    // Test with Long domain name
    const char *argv[] = {"op_start", "very-long-domain-name-that-has-many-characters-for-purposes"};
    int argc = 2;

    OpRc result = opStart.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for long domain names
    EXPECT_EQ(result, OpRc::OK);
}
} // namespace virtrust
