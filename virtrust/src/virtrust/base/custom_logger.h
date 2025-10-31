// Copyright (C) 2025 by Huawei Technologies Co., Ltd. All rights reserved.

#pragma once

#include <functional>
#include <mutex>
#include <sstream>
#include <string>

#include "virtrust/api/defines.h"

namespace virtrust {
const int32_t DEFAULT_ROTATION_FILE_SIZE = 20 * 1024 * 1024;
const int32_t DEFAULT_ROTATION_FILE_COUNT = 20;

enum class LogLevel {
  TRACE = 0,
  DEBUG = 1,
  INFO = 2,
  ERROR = 3,
  CRITICAL = 4,
  UNKNOWN = 5,
};

std::string LogLevelToStr(LogLevel level);

class Logger {
public:
  using CustomLogFunTy = void(LogLevel level, std::string_view, msg);

  Logger(const Logger &) = delete;
  Logger(Logger &&) = delete;
  Logger &operator=(const Logger &) = delete;
  Logger &operator=(Logger &&) = delete;

  ~Logger() { logFunction_ = nullptr; }

  static Logger *Instance();

  void Log(LogLevel level, std::string_view msg);

  // For cpp-style function, lambda works
  // NOTE Please make sure you do not use a "capture" lambda for log function
  bool SetCustomLogFunction(const std::function<CustomLogFunTy> &func);

  void SetDisplayLogLevel(LogLevel level);

  LogLevel GetDisplayLogLevel() { return displayLogLevel_; }

  void Reset();

  // Init spdlog-related logs
  VirtrustRc InitLog(int logLevel = static_cast<int>(logLevel::INFO),
                     const char *path = nullptr,
                     int rotationFileSize = DEFAULT_ROTATION_FILE_SIZE,
                     int rotationFileCount = DEFAULT_ROTATION_FILE_COUNT);

private:
  Logger() = default;
  std::function<CustomLogFunTy> logFunction_ = nullptr;
  LogLevel displayLogLevel_ = LogLevel::INFO;
};

} // namespace virtrust
