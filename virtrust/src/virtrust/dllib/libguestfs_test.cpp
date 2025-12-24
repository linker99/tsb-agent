/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "gtest/gtest.h"

#include "virtrust/dllib/libguestfs.h"

namespace virtrust {

TEST(LibGuestfsTest, works)
{
    // Init
    auto &libguestfs = Libguestfs::GetInstance();
    EXPECT_EQ(libguestfs.CheckOk(), DllibRc::OK);

    // Explicity reload
    auto ret = libguestfs.Reload();
    EXPECT_EQ(ret, DllibRc::OK);

    // Call Function
    auto *g = libguestfs.guestfs_create();
    EXPECT_NE(g, nullptr);

    // quit
    if (g != nullptr) {
        libguestfs.guestfs_close(g);
    }
}

TEST(LibGuestfsTest, SingletonPattern)
{
    // Test that libguestfs follow singleton pattern
    auto &libguestfs1 = Libguestfs::GetInstance();
    auto &libguestfs2 = Libguestfs::GetInstance();
    EXPECT_EQ(&libguestfs1, &libguestfs2);
}

TEST(LibGuestfsTest, CheckOkFunction)
{
    // Test the CheckOk function
    auto &libguestfs = Libguestfs::GetInstance();
    EXPECT_EQ(libguestfs.CheckOk(), DllibRc::OK);
}

TEST(LibGuestfsTest, ReloadFunction)
{
    // Test reloading functionality
    auto &libguestfs = Libguestfs::GetInstance();

    // check inital state
    EXPECT_EQ(libguestfs.CheckOk(), DllibRc::OK);

    // Reload the library
    auto ret = libguestfs.Reload();
    EXPECT_EQ(ret, DllibRc::OK);

    // Verify it's still working after reload
    EXPECT_EQ(libguestfs.CheckOk(), DllibRc::OK);
}

TEST(LibGuestfsTest, FunctionPointerValidity)
{
    // Test that all function pointer are valid
    auto &libguestfs = Libguestfs::GetInstance();

    // Test a few key functions for validity
    EXPECT_NE(libguestfs.guestfs_create.Get(), nullptr);
    EXPECT_NE(libguestfs.guestfs_launch.Get(), nullptr);
    EXPECT_NE(libguestfs.guestfs_close.Get(), nullptr);

    // Test that functions can be called (without actually executing)
    EXPECT_FALSE(libguestfs.guestfs_create.GetName().empty());
    EXPECT_FALSE(libguestfs.guestfs_launch.GetName().empty());
    EXPECT_FALSE(libguestfs.guestfs_close.GetName().empty());
}
} // namespace virtrust