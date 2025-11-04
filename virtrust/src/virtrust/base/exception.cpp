// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#include "virtrust/base/exception.h"

#include <numeric>

#include "spdlog/fmt/fmt.h"

namespace virtrust {
EnforceNotMet::EnforceNotMet(const char *file, const int line, const char *condition, const std::string &msg)
    : msgStack_{fmt::format("[Enforce fail at {}:{}] {}. {}", file, line, condition, msg)}
{
    fullMsg_ = this->msg();
}

std::string EnforceNotMet::msg() const
{
    return std::accumulate(msgStack_.begin(), msgStack_.end(), std::string(""));
}

const char *EnforceNotMet::what() const noexcept
{
    return fullMsg_.c_str();
}

} // namespace virtrust
