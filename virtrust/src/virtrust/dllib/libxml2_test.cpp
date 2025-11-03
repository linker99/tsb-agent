/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
*/

#include "gtest/gtest.h"

#include "virtrust/dllib/libxml2.h"

namespace virtrust {
    
    TEST(Libxml2Test, works)
    {
        // Init
        auto& libxml2 = Libxml2::GetInstance();
        EXPECT_EQ(libxml2.CheckOK(), DllibRc::OK);

        // Explicity reload
        auto ret = libxml2.Reload();
        EXPECT_EQ(ret, DllibRc::OK);

        // Call Function
        auto *fun_ret = libxml2.xmlParseFile("12312"); // with wrong param
        EXPECT_EQ(fun_ret, nullptr);
    }
        
    TEST(Libxml2Test, SingletonPattern)
    {
        // Test that libxml2 follows singleton pattern
        auto& libxml21 = Libxml2::GetInstance();
        auto& libxml22 = Libxml2::GetInstance();
        EXPECT_EQ(&libxml21, &libxml22);
    }
    
    TEST(Libxml2Test, CheckOKFunction)
    {
        // Test the CheckOK function
        auto& libxml2 = Libxml2::GetInstance();
        EXPECT_EQ(libxml2.CheckOK(), DllibRc::OK);

        // Test size function
        EXPECT_GT(libxml2.size(), (size_t)0);
    }
    
    TEST(Libxml2Test, ReloadFunction)
    {
        // Test reloading functionality
        auto& libxml2 = Libxml2::GetInstance();

        // check inital state
        EXPECT_EQ(libxml2.CheckOK(), DllibRc::OK);

        // Reload the library
        auto ret = libxml2.Reload();
        EXPECT_EQ(ret, DllibRc::OK);

        // Verify it's still working after reload
        EXPECT_EQ(libxml2.CheckOK(), DllibRc::OK);
    }
    
    TEST(Libxml2Test, FunctionPointerValidity)
    {
        // Test that all function pointer are valid
        auto& libxml2 = Libxml2::GetInstance();

        // Test a few key functions for validity
        EXPECT_NE(libxml2.xmlParseFile.Get(), nullptr);
        EXPECT_NE(libxml2.xmlFreeDoc.Get(), nullptr);
        EXPECT_NE(libxml2.xmlDocGetRootElement.Get(), nullptr);

        // Test that functions can be called (without actaully executing)
        EXPECT_FALSE(libxml2.xmlParseFile.GetName());
        EXPECT_FALSE(libxml2.xmlFreeDoc.GetName());
        EXPECT_FALSE(libxml2.xmlDocGetRootElement.GetName());
    }
    
    TEST(Libxml2Test, XmlParsingFunctionality)
    {
        // Test xml parsing functionality with invalid file
        auto& libxml2 = Libxml2::GetInstance();

        // Test that xmlParseFile returns nullptr for invalid file (expected behavior)
        auto *doc = libxml2.xmlParseFile("nonexistent.xml");
        EXPECT_EQ(doc, nullptr);

        // Test that we can xmlFreeDoc on nullptr (should not crash)
        libxml2.xmlFreeDoc(nullptr);
    }
} // namespace virtrust