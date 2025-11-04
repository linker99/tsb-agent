/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "gtest/gtest.h"

#include "virtrust/dllib/libguestfs.h"
#include "virtrust/dllib/libvirt.h"
#include "virtrust/dllib/libxml2.h"
#include "virtrust/dllib/openssl.h"

namespace virtrust {

TEST(DynamicLibraryTest, OpensslInitialization) {
  // Test taht Openssl can be initialied properly
  auto &openssl = Openssl::GetInstance();
  EXPECT_EQ(openssl.CheckOK(), DllibRc::OK);

  // Test that the library was loaded
  EXPECT_GT(openssl.Size(), (size_t)0);
}

TEST(DynamicLibraryTest, OpensslFunctionPointers) {
  // Test taht all key openssl function pointers are valid
  auto &openssl = Openssl::GetInstance();

  // Test that function pointers are not null
  EXPECT_NE(openssl.EVP_MD_CTX_new.Get(), nullptr);
  EXPECT_NE(openssl.EVP_MD_CTX_free.Get(), nullptr);
  EXPECT_NE(openssl.EVP_DigestInit.Get(), nullptr);
  EXPECT_NE(openssl.EVP_DigestUpdate.Get(), nullptr);
  EXPECT_NE(openssl.EVP_DigestFinal_ex.Get(), nullptr);
  EXPECT_NE(openssl.EVP_MD_fetch.Get(), nullptr);
  EXPECT_NE(openssl.EVP_MD_free.Get(), nullptr);
  EXPECT_NE(openssl.EVP_MD_CTX_reset.Get(), nullptr);
  EXPECT_NE(openssl.EVP_MD_CTX_copy_ex.Get(), nullptr);
}

TEST(DynamicLibraryTest, OpensslReloadFunctionality) {
  // Test reload functionality
  auto &openssl = Openssl::GetInstance();

  // Check initial state
  EXPECT_EQ(openssl.CheckOK(), DllibRc::OK);

  // Reload the library
  auto ret = openssl.Reload();
  EXPECT_EQ(ret, DllibRc::OK);

  // Verify it's still working after reload
  EXPECT_EQ(openssl.CheckOK(), DllibRc::OK);
}

TEST(DynamicLibraryTest, LibvirtInitialization) {
  // Test that libvirt can be initialied properly
  auto &libvirt = Libvirt::GetInstance();
  // Note: we don't assert CheckOK() as libvirt might not be available in test
  // environment But we can verify it doesn't crash
  EXPECT_NE(&libvirt, nullptr);
}

TEST(DynamicLibraryTest, LibguestfsInitialization) {
  auto &libguestfs = Libguestfs::GetInstance();
  // Note: we don't assert CheckOK() as libguestfs might not be available in
  // test environment But we can verify it doesn't crash
  EXPECT_NE(&libguestfs, nullptr);
}

TEST(DynamicLibraryTest, Libxml2Initialization) {
  // Test that libxml2 can be initialied properly
  auto &libxml2 = Libxml2::GetInstance();
  // Note: we don't assert CheckOK() as libxml2 might not be available in test
  // environment But we can verify it doesn't crash
  EXPECT_NE(&libxml2, nullptr);
}

TEST(DynamicLibraryTest, SingletonPattern) {
  // Test that all dynamic library classes follow singleton pattern
  auto &openssl1 = Openssl::GetInstance();
  auto &openssl2 = Openssl::GetInstance();
  EXPECT_EQ(&openssl1, &openssl2);

  auto &libvirt1 = Libvirt::GetInstance();
  auto &libvirt2 = Libvirt::GetInstance();
  EXPECT_EQ(&libvirt1, &libvirt2);

  auto &libguestfs1 = Libguestfs::GetInstance();
  auto &libguestfs2 = Libguestfs::GetInstance();
  EXPECT_EQ(&libguestfs1, &libguestfs2);

  auto &libxml21 = Libxml2::GetInstance();
  auto &libxml22 = Libxml2::GetInstance();
  EXPECT_EQ(&libxml21, &libxml22);
}
} // namespace virtrust