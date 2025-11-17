/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#pragma once

#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace virtrust {

inline void MakeStringInternal(std::stringstream &)
{}

template <typename T> inline void MakeStringInternal(std::stringstream &ss, const T &t)
{
    ss << t;
}

template <> inline void MakeStringInternal(std::stringstream &ss, const std::stringstream &t)
{

    ss << t.str();
}

template <typename T, typename... Args>
inline void MakeStringInternal(std::stringstream &ss, const T &t, const Args &...args)
{
    MakeStringInternal(ss, t);
    MakeStringInternal(ss, args...);
}

template <typename... Args> std::string MakeString(const Args &...args)
{
    std::stringstream ss;
    MakeStringInternal(ss, args...);
    return std::string(ss.str());
}

template <typename T> std::string MakeString(const std::vector<T> &v, const std::string &delim = " ")
{
    std::stringstream ss;
    for (auto it = v.begin(); it != v.end(); ++it) {
        if (it != v.begin()) {
            MakeStringInternal(ss, delim);
        }
        MakeStringInternal(ss, *it);
    }
    return std::string(ss.str());
}

template <> inline std::string MakeString(const std::string &args)
{
    return args;
}

inline std::string MakeString(const char *cstr)
{
    return {cstr};
}

void StrSplit(std::string_view src, std::string_view sep, std::vector<std::string> &out);

inline std::vector<std::string> StrSplit(std::string_view src, std::string_view sep)
{
    std::vector<std::string> out;
    StrSplit(src, sep, out);
    return out;
}

// 按照空白符分割字符串
inline std::vector<std::string> StrSplit(const std::string &str)
{
    std::istringstream iss(str);
    std::vector<std::string> rets;
    std::string token;
    while (iss >> token) { // 自动按空白分割病跳过多余空白
        rets.push_back(token);
    }
    return rets;
}
// 去除收尾的指定字符
inline std::string StrTrim(const std::string &str, char ch)
{

    if (str.empty()) {
        return str;
    }
    size_t start = str.find_first_not_of(ch);
    if (start == std::string::npos) {
        return ""; // 全是目标字符
    }
    size_t end = str.find_last_not_of(ch);
    return str.substr(start, end - start + 1);
}

// 去除首尾的空白符
inline std::string StrTrimWhitespace(const std::string &str)
{
    const std::string whitespace = " \t\n\v\f\r";
    size_t start = str.find_first_not_of(whitespace);
    if (start == std::string::npos) {
        return "";
    }
    size_t end = str.find_last_not_of(whitespace);
    return str.substr(start, end - start + 1);
}

// 统计字符出现次数

inline size_t StrCountChar(const std::string &str, char target)
{
    int cnt = 0;
    for (const char ch : str) {
        if (ch == target) {
            cnt++;
        }
    }
    return cnt;
}

inline bool StrStartsWith(std::string_view s, std::string_view prefix)
{
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

inline bool StartsWithIgnoreSpaces(const std::string &str, std::string_view prefix)
{
    size_t start = str.find_first_not_of(' ');
    if (start == std::string::npos) {
        return false;
    }
    return str.substr(start).find(prefix) == 0;
}

inline std::string ReadFile(const std::string &filename)
{
    std::ifstream file(filename);
    return {(std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>()};
}

inline std::vector<std::string> ExtractStringsFromBinary(std::string_view content, const size_t minLen = 4)
{
    std::vector<std::string> out;
    std::string cur;

    for (const char c: content) {
        const unsigned char uc = static_cast<unsigned char>(c);
        // the blank space is in isprint()
        if (isprint(uc) || c == '\t') {
            cur.push_back(c);
        } else {
            if (cur.size() >= minLen) {
                out.emplace_back(cur);
            }
            cur.clear();
        }
    }

    if (cur.size() >= minLen) {
        out.emplace_back(cur);
    }

    return out;
}
} // namespace virtrust
