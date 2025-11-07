/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#pragma once

#include <optional>

#include "virtrust/link/defines.h"

namespace virtrust {
std::optional<LinkConfig> MakeLinkConfigFromJsonFile(const std::string &configPath);
} // namespace virtrust
