/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "gtest/gtest.h"

#include "virtrust-sh/operator/op_undefine.h"

namespace virtrust {

TEST(OpUndefineTest, ParseArgvValidArgumentsTest)
{
    OpUndefine opUndefine;

    // Test with valid domain name
    const char *argv[] = {"op_undefine", "test_doamin"};
    int argc = 2;

    OpRc result = opUndefine.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for valid arguments
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpUndefineTest, ParseArgvHelpFlagTest)
{
    OpUndefine opUndefine;

    // Test with help Flag
    const char *argv[] = {"op_undefine", "--help"};
    int argc = 2;

    OpRc result = opUndefine.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for help flag (should not execute)
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpUndefineTest, ParseArgvHelpShortFlagTest)
{
    OpUndefine opUndefine;

    // Test with help Flag
    const char *argv[] = {"op_undefine", "-h"};
    int argc = 2;

    OpRc result = opUndefine.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for short help flag (should not execute)
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpUndefineTest, ParseArgvMissingDoaminTest)
{
    OpUndefine opUndefine;

    // Test with missig domain name arguments
    const char *argv[] = {"op_undefine"};
    int argc = 1;

    OpRc result = opUndefine.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns ERROR for misssing arguments
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpUndefineTest, ParseArgvExtraArgumentsTest)
{
    OpUndefine opUndefine;

    // Test with extra arguments
    const char *argv[] = {"op_undefine", "domain1", "extra_arg"};
    int argc = 3;

    OpRc result = opUndefine.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns ERROR for extra arguments
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpUndefineTest, ParseArgvInvalidOptionTest)
{
    OpUndefine opUndefine;

    // Test with invalid option
    const char *argv[] = {"op_undefine", "--invalid-option"};
    int argc = 2;

    OpRc result = opUndefine.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns ERROR for invalid option
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpUndefineTest, ParseArgvDomainNameStorageTest)
{
    OpUndefine opUndefine;

    // Test with domain name is properly stored
    const char *argv[] = {"op_undefine", "complex-domain-123"};
    int argc = 2;

    OpRc result = opUndefine.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK and domain name is stored
    EXPECT_EQ(result, OpRc::OK);
    // Note: Cannot directly access private member domainName_ for verification
    // but we can verify the function doesn't crash and handles correctly
}

TEST(OpUndefineTest, ParseArgvComplexDomainNameTest)
{
    OpUndefine opUndefine;

    // Test with complex domain name containing special characters
    const char *argv[] = {"op_undefine", "complex-dimain-name.123"};
    int argc = 2;

    OpRc result = opUndefine.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for complex domain names
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpUndefineTest, ParseArgvLongDomainNameTest)
{
    OpUndefine opUndefine;

    // Test with Long domain name
    const char *argv[] = {"op_undefine", "very-long-domain-name-that-has-many-characters-for-purposes"};
    int argc = 2;

    OpRc result = opUndefine.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for long domain names
    EXPECT_EQ(result, OpRc::OK);
}
} // namespace virtrust
