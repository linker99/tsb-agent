/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "gtest/gtest.h"

#include "virtrust/dllib/libvirt.h"

namespace virtrust {

TEST(LibvirtTest, works)
{
    // Init
    auto &libvirt = Libvirt::GetInstance();
    EXPECT_EQ(libvirt.CheckOk(), DllibRc::OK);

    // Explicity reload
    auto ret = libvirt.Reload();
    EXPECT_EQ(ret, DllibRc::OK);
}

TEST(LibvirtTest, SingletonPattern)
{
    // Test that libvirt follow singleton pattern
    auto &libvirt1 = Libvirt::GetInstance();
    auto &libvirt2 = Libvirt::GetInstance();
    EXPECT_EQ(&libvirt1, &libvirt2);
}

TEST(LibvirtTest, CheckOkFunction)
{
    // Test the CheckOk function
    auto &libvirt = Libvirt::GetInstance();
    EXPECT_EQ(libvirt.CheckOk(), DllibRc::OK);

    // Test size function
    EXPECT_GT(libvirt.Size(), (size_t)0);
}

TEST(LibvirtTest, ReloadFunction)
{
    // Test reloading functionality
    auto &libvirt = Libvirt::GetInstance();

    // check inital state
    EXPECT_EQ(libvirt.CheckOk(), DllibRc::OK);

    // Reload the library
    auto ret = libvirt.Reload();
    EXPECT_EQ(ret, DllibRc::OK);

    // Verify it's still working after reload
    EXPECT_EQ(libvirt.CheckOk(), DllibRc::OK);
}

TEST(LibvirtTest, FunctionPointerValidity)
{
    // Test that all function pointer are valid
    auto &libvirt = Libvirt::GetInstance();

    // Test a few key functions for validity
    EXPECT_NE(libvirt.virConnectOpen.Get(), nullptr);
    EXPECT_NE(libvirt.virDomainLookupByName.Get(), nullptr);
    EXPECT_NE(libvirt.virDomainFree.Get(), nullptr);

    // Test that functions can be called (without actually executing)
    EXPECT_FALSE(libvirt.virConnectOpen.GetName().empty());
    EXPECT_FALSE(libvirt.virDomainLookupByName.GetName().empty());
    EXPECT_FALSE(libvirt.virDomainFree.GetName().empty());
}

TEST(LibvirtTest, SetErrorFunction)
{
    // Test the SetErrorFunction functionality
    auto &libvirt = Libvirt::GetInstance();

    // Test that SetErrorFunction can be called without crashing
    auto ret = libvirt.SetErrorFunction(nullptr);
    EXPECT_EQ(ret, DllibRc::OK);
}
} // namespace virtrust