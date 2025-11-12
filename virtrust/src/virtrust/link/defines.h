/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include "virtrust/base/logger.h"

namespace virtrust {
enum class LinkRc : uint32_t {
    OK = 0,
    ERROR = 1,
};

constexpr uint16_t WAIT_RUN_SERVER_SECONDS = 2;

struct LinkConfig {
    std::string caPath;
    std::string certPath;
    std::string skPath;
    std::string ip;
    std::string ipMask;
    uint16_t port;
    std::string udsPath;
};

class ConfigMgr {
public:
    static ConfigMgr &Instance()
    {
        static ConfigMgr instance;
        return instance;
    }
    void SetLinkConfig(const LinkConfig &config)
    {
        linkConfig_ = config;
    }
    LinkConfig GetLinkConfig()
    {
        return linkConfig_;
    }

private:
    LinkConfig linkConfig_;
};

struct MigrationConfig {
    std::string domainName;
    std::string uuid;
    std::string destUri;
    std::string localUri;
    unsigned int flags;
};

} // namespace virtrust