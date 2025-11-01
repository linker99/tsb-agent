/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
*/

#include "gtest/gtest.h"

#include "virtrust-sh/operator/op_migrate.h"

namespace virtrust {

    TEST(OpMigrateTest, ParseArgvValidArgumentsTest)
    {
        OpMigrate opMigrate;

        // Test with valid domain name and destination URI
        const char *argv[] = {"op_migrate", "test_doamin", "qemu+ssh://destination.example.com/system"};
        int argc = 3;

        OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

        // Verify ParseArgv returns OK for valid arguments
        EXPECT_EQ(result, OpRc::OK);
    }

    TEST(OpMigrateTest, ParseArgvHelpFlagTest)
    {
        OpMigrate opMigrate;

        // Test with help Flag
        const char *argv[] = {"op_migrate", "--help"};
        int argc = 2;

        OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

        // Verify ParseArgv returns OK for help flag (should not execute)
        EXPECT_EQ(result, OpRc::OK);
    }

    TEST(OpMigrateTest, ParseArgvHelpShortFlagTest)
    {
        OpMigrate opMigrate;

        // Test with help Flag
        const char *argv[] = {"op_migrate", "-h"};
        int argc = 2;

        OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

        // Verify ParseArgv returns OK for short help flag (should not execute)
        EXPECT_EQ(result, OpRc::OK);
    }

    TEST(OpMigrateTest, ParseArgvMissingArgumentsTest)
    {
        OpMigrate opMigrate;

        // Test with missig arguments (only program name) 
        const char *argv[] = {"op_migrate"};
        int argc = 1;

        OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

        // Verify ParseArgv returns ERROR for misssing arguments
        EXPECT_EQ(result, OpRc::ERROR);
    }

    TEST(OpMigrateTest, ParseArgvMissingDestinationTest)
    {
        OpMigrate opMigrate;

        // Test with aonly domain name, missing destination URI
        const char *argv[] = {"op_migrate", "test_domain"};
        int argc = 2;

        OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

        // Verify ParseArgv returns ERROR for missing destination
        EXPECT_EQ(result, OpRc::ERROR);
    }

    TEST(OpMigrateTest, ParseArgvExtraArgumentsTest)
    {
        OpMigrate opMigrate;

        // Test with extra arguments
        const char *argv[] = {"op_migrate", "domain1", "dest_uri", "extra_arg"};
        int argc = 4;

        OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

        // Verify ParseArgv return ERROR for extra arguments
        EXPECT_EQ(result, OpRc::ERROR);
    }

    TEST(OpMigrateTest, ParseArgvInvalidOptionTest)
    {
        OpMigrate opMigrate;

        // Test with invalid option
        const char *argv[] = {"op_migrate", "--invalid-option"};
        int argc = 2;

        OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

        // Verify ParseArgv returns ERROR for invalid option
        EXPECT_EQ(result, OpRc::ERROR);
    }

    TEST(OpMigrateTest, ParseArgvComplexArgumentsTest)
    {
        OpMigrate opMigrate;

        // Test with complex domain name and URI
        const char *argv[] = {"op_migrate", "complex-domain-name-123", "qemu+ssh://user@host:22/system?param=value"};
        int argc = 3;

        OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

        // Verify ParseArgv returns ERROR for complex arguments
        EXPECT_EQ(result, OpRc::OK);
    }

    TEST(OpMigrateTest, ParseArgvFlagCombinationTest)
    {
        OpMigrate opMigrate;

        // Test with special characters in arguments
        const char *argv[] = {"op_migrate", "test-dimain_123", "qemu+ssh://user@host.example.com:22/system"};
        int argc = 3;

        OpRc result = opMigrate.ParseArgv(argc, const_cast<char **>(argv));

        // Verify ParseArgv returns OK for special characters
        EXPECT_EQ(result, OpRc::OK);
    }
} // namespace virtrust