// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#pragma once

#include <exception>
#include <functional>
#include <vector>

#include "virtrust/base/str_utils.h"

namespace virtrust {
class EnforceNotMet : public std::exception {
public:
    EnforceNotMet(const char *file, const int line, const char *condition, const std::string &msg);
    std::string msg() const;

    inline const std::vector<std::string> &msg_stack() const
    {
        return msgStack_;
    }

    virtual const char *what() const noexcept override;

private:
    std::vector<std::string> msgStack_;
    std::string fullMsg_;
};

#define VIRTRUST_ENFORCE(condition, ...)                                                                          \
    do {                                                                                                          \
        if (!(condition)) {                                                                                       \
            throw ::virtrust::EnforceNotMet(__FILE__, __LINE__, #condition, ::virtrust::MakeString(__VA_ARGS__)); \
        }                                                                                                         \
    } while (false)

// Check condition, and returns error code on error
#define VIRTRUST_CHECK_ROF(condition, error_code, ...) \
    do {                                               \
        if (!(condition)) {                            \
            VIRTRUST_ERROR(__VA_ARGS__);               \
            return error_code;                         \
        }                                              \
    } while (false)

namespace enforce_detail {

struct EnforceOK {};

class EnforceFailMessage {
public:
    constexpr EnforceFailMessage(EnforceOK) : msg_(nullptr)
    {}

    EnforceFailMessage(EnforceFailMessage &&) = default;
    EnforceFailMessage(const EnforceFailMessage &) = delete;
    EnforceFailMessage &operator=(EnforceFailMessage &&) = delete;
    EnforceFailMessage &operator=(const EnforceFailMessage &) = delete;

    EnforceFailMessage(std::string &&msg)
    {
        msg_ = new std::string(std::move(msg));
    }

    inline bool bad() const
    {
        return msg_ != nullptr;
    }

    std::string get_message_and_free(std::string &&extra) const
    {
        std::string r;
        if (extra.empty()) {
            r = std::move(*msg_);
        } else {
            r = ::virtrust::MakeString(*msg_, ". ", extra);
        }
        delete msg_;
        return r;
    }

private:
    std::string *msg_ = nullptr;
};

#define BINARY_COMP_HELPER(name, op)                                                             \
    template <typename T1, typename T2> inline EnforceFailMessage name(const T1 &x, const T2 &y) \
    {                                                                                            \
        if (x op y) {                                                                            \
            return EnforceOK();                                                                  \
        }                                                                                        \
        return MakeString(x, " vs ", y);                                                         \
    }

BINARY_COMP_HELPER(Equals, ==)
BINARY_COMP_HELPER(NotEquals, !=)
BINARY_COMP_HELPER(Greater, >)
BINARY_COMP_HELPER(GreaterEquals, >=)
BINARY_COMP_HELPER(Less, <)
BINARY_COMP_HELPER(LessEquals, <=)
#undef BINARY_COMP_HELPER

#define VIRTRUST_ENFORCE_THAT_IMPL(condition, expr, ...)                                      \
    do {                                                                                      \
        const ::virtrust::enforce_detail::EnforceFailMessage r = (condition);                 \
        if (r.bad()) {                                                                        \
            throw ::virtrust::EnforceNotMet(__FILE__, __LINE__, expr,                         \
                                            r.get_message_and_free(MakeString(__VA_ARGS__))); \
        }                                                                                     \
    } while (false)

#define VIRTRUST_ENFORCE_THAT(condition, ...) VIRTRUST_ENFORCE_THAT_IMPL((condition), #condition, __VA_ARGS__)

} // namespace enforce_detail

#define VIRTRUST_ENFORCE_EQ(x, y, ...) \
    VIRTRUST_ENFORCE_THAT_IMPL(::virtrust::enforce_detail::Equals((x), (y)), #x "==" #y, __VA_ARGS__)

#define VIRTRUST_ENFORCE_NE(x, y, ...) \
    VIRTRUST_ENFORCE_THAT_IMPL(::virtrust::enforce_detail::NotEquals((x), (y)), #x "!=" #y, __VA_ARGS__)

#define VIRTRUST_ENFORCE_LE(x, y, ...) \
    VIRTRUST_ENFORCE_THAT_IMPL(::virtrust::enforce_detail::LessEquals((x), (y)), #x "<=" #y, __VA_ARGS__)

#define VIRTRUST_ENFORCE_LT(x, y, ...) \
    VIRTRUST_ENFORCE_THAT_IMPL(::virtrust::enforce_detail::Less((x), (y)), #x "<" #y, __VA_ARGS__)

#define VIRTRUST_ENFORCE_GE(x, y, ...) \
    VIRTRUST_ENFORCE_THAT_IMPL(::virtrust::enforce_detail::GreaterEquals((x), (y)), #x ">=" #y, __VA_ARGS__)

#define VIRTRUST_ENFORCE_GT(x, y, ...) \
    VIRTRUST_ENFORCE_THAT_IMPL(::virtrust::enforce_detail::Greater((x), (y)), #x ">" #y, __VA_ARGS__)

} // namespace virtrust
