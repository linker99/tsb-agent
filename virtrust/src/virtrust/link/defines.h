/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

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

struct LinkConfig {
  std::string caPath;
  std::string certPath;
  std::string skPath;
  std::string ip;
  std::string ipMask;
  uint16_t port;
};

} // namespace virtrust