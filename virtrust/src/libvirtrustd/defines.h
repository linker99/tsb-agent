/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <array>
#include <cstdint>
#include <string_view>

namespace virtrust {
// version
constexpr std::string_view LIBVIRTRUSTD_VERSION = "1.0.0";

// default values
constexpr std::string_view LIBVIRTRUSTD_SERVER_ADDR = "127.0.0.1";
constexpr std::string_view LIBVIRTRUSTD_SERVER_ADDR_MASK = "127.0.0.1/8";
constexpr std::string_view LIBVIRTRUSTD_CA_PATH = "ca-cert.pem";
constexpr std::string_view LIBVIRTRUSTD_CERT_PATH = "server-cert.pem";
constexpr std::string_view LIBVIRTRUSTD_SK_PATH = "server-sk.pem";
constexpr uint16_t LIBVIRTRUSTD_SERVER_PORT = 10086;
} // namespace virtrust
