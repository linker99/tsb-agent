// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#pragma once

#include <string_view>

namespace virtrust {
constexpr std::string_view VIRTRUST_SH_VERSION = "1.0.0";
constexpr std::string_view VIRTRUST_SH_VIRT_INSTALL_PATH =
    "/usr/bin/virt-install";
constexpr std::string_view VIRTRUST_SH_LOGFILE_NAME = "virtrust.log";
constexpr int VIRTRUST_SH__CMD_STR_MAX_LEN = 1024;
} // namespace virtrust
