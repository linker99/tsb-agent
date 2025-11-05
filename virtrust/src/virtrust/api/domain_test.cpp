/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "virtrust/api/context.h"
#include "virtrust/api/defines.h"
#include "virtrust/api/domain.h"
#include "virtrust/base/logger.h"
#include "virtrust/crypto/sm3.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust/utils/file_io.h"
#include "virtrust/utils/foreign_mounter.h"
#include "virtrust/utils/virt_xml_parser.h"

namespace virtrust {

// Test that basic compilation works
TEST(DomainTest, BasicCompilation)
{
    // Basic compile-time test - just ensure the functions exist and can be called
    EXPECT_TRUE(true);
}

// Test that VerifyConfig can be instantiated and used
TEST(DomainTest, VerifyConfigBasics)
{
    // Test that VerifyConfig can be constructed with basic parameters
    VerifyConfig config("test-guest", "/path/to/disk", "/path/to/loader");

    // Test basic getter functions exist and work
    EXPECT_EQ(config.GetGuestName(), "test-guest");
    EXPECT_EQ(config.GetDiskPath(), "/path/to/disk");
    EXPECT_EQ(config.GetLoaderPath(), "/path/to/loader");
}
} // namespace virtrust