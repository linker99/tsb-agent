/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "gtest/gtest.h"

#include "virtrust/dllib/openssl.h"

namespace virtrust {

TEST(OpensslTest, works)
{
    // Init
    auto &openssl = Openssl::GetInstance();
    EXPECT_EQ(openssl.CheckOk(), DllibRc::OK);

    // Explicity reload
    auto ret = openssl.Reload();
    EXPECT_EQ(ret, DllibRc::OK);

    // Call Function
    auto *ptr = openssl.EVP_MD_CTX_new();
    EXPECT_NE(ptr, nullptr);

    // Quit
    openssl.EVP_MD_CTX_free(ptr);
}

TEST(OpensslTest, SingletonPattern)
{
    // Test that openssl follows singleton pattern
    auto &openssl1 = Openssl::GetInstance();
    auto &openssl2 = Openssl::GetInstance();
    EXPECT_EQ(&openssl1, &openssl2);
}

TEST(OpensslTest, CheckOkFunction)
{
    // Test the CheckOk function
    auto &openssl = Openssl::GetInstance();
    EXPECT_EQ(openssl.CheckOk(), DllibRc::OK);

    // Test size function
    EXPECT_GT(openssl.Size(), (size_t)0);
}

TEST(OpensslTest, ReloadFunction)
{
    // Test reloading functionality
    auto &openssl = Openssl::GetInstance();

    // check inital state
    EXPECT_EQ(openssl.CheckOk(), DllibRc::OK);

    // Reload the library
    auto ret = openssl.Reload();
    EXPECT_EQ(ret, DllibRc::OK);

    // Verify it's still working after reload
    EXPECT_EQ(openssl.CheckOk(), DllibRc::OK);
}

TEST(OpensslTest, FunctionPointerValidity)
{
    // Test that all function pointer are valid
    auto &openssl = Openssl::GetInstance();

    // Test a few key functions for validity
    EXPECT_NE(openssl.EVP_MD_CTX_new.Get(), nullptr);
    EXPECT_NE(openssl.EVP_MD_CTX_free.Get(), nullptr);
    EXPECT_NE(openssl.EVP_DigestInit.Get(), nullptr);

    // Test that functions can be called (without actually executing)
    EXPECT_FALSE(openssl.EVP_MD_CTX_new.GetName().empty());
    EXPECT_FALSE(openssl.EVP_MD_CTX_free.GetName().empty());
    EXPECT_FALSE(openssl.EVP_DigestInit.GetName().empty());
}

TEST(OpensslTest, DigestFunctionality)
{
    // Test basic functionality
    auto &openssl = Openssl::GetInstance();

    // Test that EVP_MD_CTX_new creates a invalid context
    auto *ctx = openssl.EVP_MD_CTX_new();
    EXPECT_NE(ctx, nullptr);

    // Test that EVP_MD_CTX_free cleans up properly
    openssl.EVP_MD_CTX_free(ctx);

    // Test that EVP_MD_CTX_reset works
    ctx = openssl.EVP_MD_CTX_new();
    EXPECT_NE(ctx, nullptr);
    EXPECT_EQ(openssl.EVP_MD_CTX_reset(ctx), 1); // Should return OPENSSL_OK
    openssl.EVP_MD_CTX_free(ctx);
}
} // namespace virtrust