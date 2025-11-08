/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "virtrust/link/defines.h"

namespace virtrust {

class LinkConfigBuilder {
public:
#define VIRTRUST_LINK_BUILDER_ADD(TYPE, NAME) \
    LinkConfigBuilder NAME(TYPE NAME)         \
    {                                         \
        config_.NAME = NAME;                  \
        return *this;                         \
    }

    VIRTRUST_LINK_BUILDER_ADD(const std::string &, caPath)
    VIRTRUST_LINK_BUILDER_ADD(const std::string &, udsPath)
    VIRTRUST_LINK_BUILDER_ADD(const std::string &, certPath)
    VIRTRUST_LINK_BUILDER_ADD(const std::string &, skPath)
    VIRTRUST_LINK_BUILDER_ADD(const std::string &, ip)
    VIRTRUST_LINK_BUILDER_ADD(const std::string &, ipMask)
    VIRTRUST_LINK_BUILDER_ADD(uint16_t, port)

#undef VIRTRUST_LINK_BUILDER_ADD

    LinkConfig Build()
    {
        return config_;
    }

private:
    LinkConfig config_;
};

} // namespace virtrust
