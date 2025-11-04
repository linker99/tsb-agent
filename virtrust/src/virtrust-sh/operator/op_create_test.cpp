/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "gtest/gtest.h"

#include "virtrust-sh/defines.h"
#include "virtrust-sh/operator/op_create.h"

namespace virtrust {

TEST(OpCreateTest, ParseArgvTest)
{
    OpCreate opCreate;

    // Test with basic arguments
    const char *argv[] = {"op_create", "--name", "test_vm", "--memory", "1024"};
    int argc = 5;

    OpRc result = opCreate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for valid arguments
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpCreateTest, ParseArgvEmptyTest)
{
    OpCreate opCreate;

    // Test with no arguments (only program name)
    const char *argv[] = {"op_create", "--name", "test_vm"};
    int argc = 3;

    OpRc result = opCreate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for edge case with no extra arguments
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpCreateTest, ParseArgvMultipleArgsTest)
{
    OpCreate opCreate;

    // Test with more complex arguments
    const char *argv[] = {"op_create", "--name", "test_vm", "--memory", "1024", "--vcpu", "2", "--disk", "size=10"};
    int argc = 9;

    OpRc result = opCreate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv returns OK for complex arguments
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpCreateTest, ParseArgvSpecialCharactersTest)
{
    OpCreate opCreate;

    // Test with more containing special arguments
    const char *argv[] = {"op_create", "--name", "test-vm_123", "--memory", "2048", "--graphics", "vnc"};
    int argc = 7;

    OpRc result = opCreate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv handles special characters correctly
    EXPECT_EQ(result, OpRc::OK);
}

TEST(OpCreateTest, ParseArgvLongArgumentsTest)
{
    OpCreate opCreate;

    // Test with long arguments names
    const char *argv[] = {"op_create", "--name", "test-long-vm-name-for-testing", "--memory", "4096", "--vcpu", "4"};
    int argc = 7;

    OpRc result = opCreate.ParseArgv(argc, const_cast<char **>(argv));

    // Verify ParseArgv handles long garuments names correctly
    EXPECT_EQ(result, OpRc::OK);
}
} // namespace virtrust
