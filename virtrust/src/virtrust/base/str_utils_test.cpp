/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "gtest/gtest.h"

#include "virtrust/base/str_utils.h"

namespace virtrust {

TEST(StrUtils, MakeString)
{
    // Test basic functionality
    EXPECT_EQ(MakeString(), "");
    EXPECT_EQ(MakeString("hello"), "hello");
    EXPECT_EQ(MakeString("hello", " ", "world"), "hello world");
    EXPECT_EQ(MakeString(123), "123");
    EXPECT_EQ(MakeString(123, " ", 456), "123 456");
    EXPECT_EQ(MakeString("Number:", 42), "Number:42");

    // Test with Vector
    std::vector<int> nums = {1, 2, 3, 4, 5};
    EXPECT_EQ(MakeString(nums), "1 2 3 4 5");

    std::vector<std::string> strs = {"a", "b", "c"};
    EXPECT_EQ(MakeString(strs), "a b c");

    // Test with custom delimiter
    EXPECT_EQ(MakeString<int>(nums, ","), "1,2,3,4,5");
}

TEST(StrUtils, Split)
{
    // Test Split with separator
    std::vector<std::string> result;
    StrSplit("a,b,c", ",", result);
    ASSERT_EQ(result.size(), (size_t)3);
    EXPECT_EQ(result[0], "a");
    EXPECT_EQ(result[1], "b");
    EXPECT_EQ(result[2], "c");

    // Test Split with empty string
    result.clear();
    StrSplit("", ",", result);
    ASSERT_EQ(result.size(), (size_t)0);

    // Test Split with no separator
    result.clear();
    StrSplit("abc", ",", result);
    ASSERT_EQ(result.size(), (size_t)1);
    EXPECT_EQ(result[0], "abc");

    // Test Split with empty separator
    result.clear();
    StrSplit("abc", "", result);
    ASSERT_EQ(result.size(), (size_t)0);

    // Test Split with multiple consecutive separators
    result.clear();
    StrSplit("a,,b,,c", ",", result);
    ASSERT_EQ(result.size(), (size_t)5);
    EXPECT_EQ(result[0], "a");
    EXPECT_EQ(result[1], "");
    EXPECT_EQ(result[2], "b");
    EXPECT_EQ(result[3], "");
    EXPECT_EQ(result[4], "c");

    // Test Split with trailing separator
    result.clear();
    StrSplit("a,b,", ",", result);
    ASSERT_EQ(result.size(), (size_t)2);
    EXPECT_EQ(result[0], "a");
    EXPECT_EQ(result[1], "b");

    // Test Split with leading separator
    result.clear();
    StrSplit(",a,b", ",", result);
    ASSERT_EQ(result.size(), (size_t)3);
    EXPECT_EQ(result[0], "");
    EXPECT_EQ(result[1], "a");
    EXPECT_EQ(result[2], "b");
}

TEST(StrUtils, SplitWithEmptyString)
{
    // Test Split with empty string (no separator)
    std::vector<std::string> result = StrSplit("a,b,c", ",");
    ASSERT_EQ(result.size(), (size_t)3);
    EXPECT_EQ(result[0], "a");
    EXPECT_EQ(result[1], "b");
    EXPECT_EQ(result[2], "c");
}

TEST(StrUtils, SplitWhitespace)
{
    // Test Split with whitespace separator
    std::vector<std::string> result = StrSplit("  hello   world  ");
    ASSERT_EQ(result.size(), (size_t)2);
    EXPECT_EQ(result[0], "hello");
    EXPECT_EQ(result[1], "world");

    // Test Split with multiple whitespace
    result = StrSplit("a\t\nb\r\fc");
    ASSERT_EQ(result.size(), (size_t)3);
    EXPECT_EQ(result[0], "a");
    EXPECT_EQ(result[1], "b");
    EXPECT_EQ(result[2], "c");

    // Test Split with empty string
    result = StrSplit("");
    ASSERT_EQ(result.size(), (size_t)0);

    // Test Split with only whitespace
    result = StrSplit("   \t\n  ");
    ASSERT_EQ(result.size(), (size_t)0);
}

TEST(StrUtils, Trim)
{
    // Test Trim with specified character
    EXPECT_EQ(StrTrim("aaaHelloaaa", 'a'), "Hello");
    EXPECT_EQ(StrTrim("bbbWorldbbb", 'b'), "World");
    EXPECT_EQ(StrTrim("Hello", 'x'), "Hello");
    EXPECT_EQ(StrTrim("aaaa", 'a'), "");
    EXPECT_EQ(StrTrim("", 'a'), "");
    EXPECT_EQ(StrTrim("  Hello  ", ' '), "Hello");
}

TEST(StrUtils, TrimWhitespace)
{
    // Test TrimWhitespace
    EXPECT_EQ(StrTrimWhitespace("  Hello  "), "Hello");
    EXPECT_EQ(StrTrimWhitespace("\t\nHello\r\f"), "Hello");
    EXPECT_EQ(StrTrimWhitespace("Hello"), "Hello");
    EXPECT_EQ(StrTrimWhitespace(""), "");
    EXPECT_EQ(StrTrimWhitespace("    "), "");
    EXPECT_EQ(StrTrimWhitespace("\t\n\r\f\v"), "");
}

TEST(StrUtils, CountChar)
{
    // Test CountChar
    EXPECT_EQ(StrCountChar("hello world", 'l'), (size_t)3);
    EXPECT_EQ(StrCountChar("abcdef", 'z'), (size_t)0);
    EXPECT_EQ(StrCountChar("", 'a'), (size_t)0);
    EXPECT_EQ(StrCountChar("aaaaaa", 'a'), (size_t)6);
    EXPECT_EQ(StrCountChar("Hello World", ' '), (size_t)1);
}

TEST(StrUtils, StartsWith)
{
    // Test StartsWith
    EXPECT_TRUE(StrStartsWith("Hello World", "Hello"));
    EXPECT_FALSE(StrStartsWith("Hello World", "World"));
    EXPECT_TRUE(StrStartsWith("Hello", "Hello"));
    EXPECT_FALSE(StrStartsWith("Hello", "Hello World"));
    EXPECT_TRUE(StrStartsWith("", ""));
    EXPECT_FALSE(StrStartsWith("", "Hello"));
    EXPECT_TRUE(StrStartsWith("Hello World", ""));
}

TEST(StrUtils, ExtractStringsFromBinary)
{
    // Test basic functionality with ASCII strings
    static const char kContent1[] = "Hello\x00\x01World\x02\x03Test";
    std::string content1(kContent1, sizeof(kContent1) - 1);

    auto result1 = ExtractStringsFromBinary(content1);
    ASSERT_EQ(result1.size(), (size_t)3);
    EXPECT_EQ(result1[0], "Hello");
    EXPECT_EQ(result1[1], "World");
    EXPECT_EQ(result1[2], "Test");

    // Test with numbers and special printable characters
    static const char kContent2[] = "Version: 1.2.3\x00Path: /usr/bin\nStatus: OK";
    std::string content2(kContent2, sizeof(kContent2) - 1);

    auto result2 = ExtractStringsFromBinary(content2);
    ASSERT_EQ(result2.size(), (size_t)3);
    EXPECT_EQ(result2[0], "Version: 1.2.3");
    EXPECT_EQ(result2[1], "Path: /usr/bin");
    EXPECT_EQ(result2[2], "Status: OK");
}
} // namespace virtrust
