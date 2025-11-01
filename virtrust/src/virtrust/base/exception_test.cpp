/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
*/

#include "gtest/gtest.h"
#include "spdlog/fmt/bundled/core.h"

#include "virtrust/base/exception.h"
#include "virtrust/base/logger.h"

namespace virtrust {

    TEST(Exception, Enforce)
    {
        ASSERT_THROW(VIRTRUST_ENFORCE(false), EnforceNotMet);
        ASSERT_NO_THROW(VIRTRUST_ENFORCE(true));
    }

    TEST(Exception, Compares)
    {
        ASSERT_THROW(VIRTRUST_ENFORCE_EQ(0, 1), EnforceNotMet);
        ASSERT_NO_THROW(VIRTRUST_ENFORCE_EQ(1, 1));

        ASSERT_THROW(VIRTRUST_ENFORCE_LE(1, 0), EnforceNotMet);
        ASSERT_NO_THROW(VIRTRUST_ENFORCE_LE(0, 1));
        ASSERT_NO_THROW(VIRTRUST_ENFORCE_LE(1, 1));

        ASSERT_THROW(VIRTRUST_ENFORCE_GE(0, 1), EnforceNotMet);
        ASSERT_NO_THROW(VIRTRUST_ENFORCE_GE(1, 0));
        ASSERT_NO_THROW(VIRTRUST_ENFORCE_GE(1, 1));

        ASSERT_THROW(VIRTRUST_ENFORCE_LT(1, 0), EnforceNotMet);
        ASSERT_NO_THROW(VIRTRUST_ENFORCE_LT(0, 1));

        ASSERT_THROW(VIRTRUST_ENFORCE_GT(0, 1), EnforceNotMet);
        ASSERT_NO_THROW(VIRTRUST_ENFORCE_Gt(1, 0));
    }

    TEST(Exception, CompareWithMessages)
    {
        try {
            VIRTRUST_ENFORCE_EQ(1, 2, "Expected 1 to equal 2");
            FAIL() << "Should have thrown EnforceNotMet exception";
        } catch (const EnforceNotMet &e) {
            EXPECT_NE(std::string(e.what()).find("1 vs 2"), std::string::npos);
            EXPECT_NE(std::string(e.what()).find("Excepted 1 to equal 2"), std::string::npos);
        }

        try {
            VIRTRUST_ENFORCE_GT(1, 2, "1 should be greater than 2");
            FAIL() << "Should have thrown EnforceNotMet exception";
        } catch (const EnforceNotMet &e) {
            EXPECT_NE(std::string(e.what()).find("1 vs 2"), std::string::npos);
            EXPECT_NE(std::string(e.what()).find("1 should be greater than 2"), std::string::npos);
        }
    }

    TEST(Exception, EnforceThat)
    {
        // Test successful enforcement
        ASSERT_NO_THROW(VIRTRUST_ENFORCE_THAT(enforce_detail::Equals(1, 1), "Values should be equal"));

        try {
            ASSERT_ENFORCE_THAT(enforce_detail::Equals(1, 2), "Values should be equal");
            FAIL() << "Should have thrown EnforceNotMet exception";
        } catch (const EnforceNotMet &e) {
            EXPECT_NE(std::string(e.what()).find("1 vs 2"), std::string::npos);
        }
    }

    TEST(Exception, )
    {
        try {
            VIRTRUST_ENFORCE(false, "Test message with ", 42);
            FAIL() << "Should have thrown EnforceNotMet exception";
        } catch (const EnforceNotMet &e) {
            // Check that the message contains the excepted content
            std::string what_msg = e.what();

            VIRTRUST_LOG_INFO(what_msg);

            EXPECT_NE(what_msg.find("Test message with 42"), std::string::npos);

            // Check that we can get the message stack
            const auto &msg_stack = e.msg_stack();
            ECPECT_FALSE(msg_stack.empty());
        }
    }
} // namespace virtrust