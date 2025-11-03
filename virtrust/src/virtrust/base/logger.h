#pragma once

#include "spdlog/fmt/fmt.h"
#include "virtrust/base/custom_logger.h"
#include "virtrust/base/str_utils.h"
#include <atomic>
#include <cstring>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <sys/time.h>

#ifndef VIRTRUST_LIKELY
#define VIRTRUST_LIKELY(x) (__builtin_expect(!!(x), 1) != 0)
#endif

#ifndef VIRTRUST_UNLIKELY
#define VIRTRUST_UNLIKELY(x) (__builtin_expect(!!(x), 0) != 0)
#endif

#ifndef VIRTRUST_LOG_FILENAME
#define VIRTRUST_LOG_FILENAME                                                  \
  (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

#define VIRTRUST_LOG(level, ...)                                               \
  do {                                                                         \
    auto logger = ::virtrust::Logger::Instance();                              \
    if (logger != nullptr) {                                                   \
      logger->Log(level,                                                       \
                  fmt::format("[VIRTRUST {}:{}]{}", VIRTRUST_LOG_FILENAME,     \
                              __LINE__, fmt::format(__VA_ARGS__)));            \
    }                                                                          \
  } while (0)

#define VIRTRUST_LOG_TRACE(...)                                                \
  VIRTRUST_LOG(::virtrust::LogLevel::TRACE, __VA_ARGS__)
#define VIRTRUST_LOG_DEBUG(...)                                                \
  VIRTRUST_LOG(::virtrust::LogLevel::DEBUG, __VA_ARGS__)
#define VIRTRUST_LOG_INFO(...)                                                 \
  VIRTRUST_LOG(::virtrust::LogLevel::INFO, __VA_ARGS__)
#define VIRTRUST_LOG_WARN(...)                                                 \
  VIRTRUST_LOG(::virtrust::LogLevel::WARN, __VA_ARGS__)
#define VIRTRUST_LOG_ERROR(...)                                                \
  VIRTRUST_LOG(::virtrust::LogLevel::ERROR, __VA_ARGS__)

#define VIRTRUST_ASSERT_LOG_RETURN(args, ret)                                  \
  if (VIRTRUST_UNLIKELY(!(args))) {                                            \
    VIRTRUST_LOG_ERROR("Assert" << #args);                                     \
    return (ret);                                                              \
  }
#define VIRTRUST_ASSERT_LOG_RETURN_VOID(args)                                  \
  if (VIRTRUST_UNLIKELY(!(args))) {                                            \
    VIRTRUST_LOG_ERROR("Assert" << #args);                                     \
    return (ret);                                                              \
  }
