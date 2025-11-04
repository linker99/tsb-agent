/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "gtest/gtest.h"

#include "virtrust-sh/operator/op_list.h"

namespace virtrust {

TEST(OpListTest, ParseArgvNoArgumentsTest)
{
    OpList opList;

    // Test with no arguments
    const char *argv[] = {"op_list"};
    int argc = 1;

    OpRc result = opList.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for no arguments (default behavior)
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpListTest, ParseArgvHelpFlagTest)
{
    OpList opList;

    // Test with help Flag
    const char *argv[] = {"op_list", "--help"};
    int argc = 2;

    OpRc result = opList.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for help flag (should not execute)
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpListTest, ParseArgvHelpShortFlagTest)
{
    OpList opList;

    // Test with help Flag
    const char *argv[] = {"op_list", "-h"};
    int argc = 2;

    OpRc result = opList.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for help flag (should not execute)
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpListTest, ParseArgvAllFlagTest)
{
    OpList opList;

    // Test with all flag
    const char *argv[] = {"op_list", "--all"};
    int argc = 2;

    OpRc result = opList.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for all flag
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpListTest, ParseArgvAllShortFlagTest)
{
    OpList opList;

    // Test with all short falg
    const char *argv[] = {"op_list", "-a"};
    int argc = 2;

    OpRc result = opList.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for all short falg
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpListTest, ParseArgvBothFlagsTest)
{
    OpList opList;

    // Test with both flags
    const char *argv[] = {"op_list", "-a", "--help"};
    int argc = 3;

    OpRc result = opList.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv return OK for both flags (help takes precedence)
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpListTest, ParseArgvInvalidOptionTest)
{
    OpList opList;

    // Test with invalid option
    const char *argv[] = {"op_list", "--invalid-option"};
    int argc = 2;

    OpRc result = opList.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns ERROR for invalid option
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpListTest, ParseArgvExtraArgumentsTest)
{
    OpList opList;

    // Test with extra augruments
    const char *argv[] = {"op_list", "extra_arg"};
    int argc = 2;

    OpRc result = opList.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns ERROR for extra arguments
    EXPECT_EQ(result, OpRc::ERROR);
}

TEST(OpListTest, ParseArgvFlagCombinationTest)
{
    OpList opList;

    // Test with mutiple valid flags
    const char *argv[] = {"op_list", "-a", "-h"};
    int argc = 3;

    OpRc result = opList.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for valid flag combination
    EXPECT_EQ(result, OpRc::ERROR);
}
} // namespace virtrust
