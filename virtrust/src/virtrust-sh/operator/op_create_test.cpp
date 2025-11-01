/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
*/

#include "gtest/gtest.h"

#include "virtrust-sh/defines.h"
#include "virtrust-sh/operator/op_create.h"

namespace virtrust {

    TEST(OpCreateTest, ParseArgvTest) {
        OpCeate opCreate;

        // Test with basic arguments
        const char *argv[] = {"op_create", "--name", "test_vm", "--memory", "1024"};
        int argc = 5;

        OpRc result = opCreate.ParseArgv(argc, const_cast<char **>(argv));

        // Verify ParseArgv returns OK for valid arguments
        EXPECT_EQ(result, OpRc::OK);
    }
}