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
    WARN = 3,
    ERROR = 4,
    CRITICAL = 5,
    UNKNOWN,
};

std::string LogLevelToStr(LogLevel level);

class Logger {
public:
    using CustomLogFunTy = void(LogLevel level, std::string_view msg);

    Logger(const Logger &) = delete;
    Logger(Logger &&) = delete;
    Logger &operator=(const Logger &) = delete;
    Logger &operator=(Logger &&) = delete;

    ~Logger()
    {
        logFunction_ = nullptr;
    }

    static Logger *Instance();

    void Log(LogLevel level, std::string_view msg);

    // For cpp-style function, lambda works
    // NOTE Please make sure you do not use a "capture" lambda for log function
    bool SetCustomLogFunction(const std::function<CustomLogFunTy> &func);

    void SetDisplayLogLevel(LogLevel level);

    LogLevel GetDisplayLogLevel()
    {
        return displayLogLevel_;
    }

    void Reset();

    /**
     * 初始化日志相关
     * @param path[IN] 日志路径 nullptr
     * 不输出到文件，要输出到文件时是带文件名的路径，路径需存在。
     * @param logLevel[IN] 日志级别 默认INFO。
     * @param rotationFileSize[IN]
     * 单个日志文件大小，单位字节bytes,默认20*1024*1024*1024（20M）范围[1*1024*1024,500*1024*1024]。
     * @param rotationFileCount[IN] 日志保存数量 超过该数量 之前日志将被删除
     * 默认20 范围[1,64]。
     * @return VirtrustRc::OK 失败错误码
     */
    VirtrustRc InitLog(int logLevel = static_cast<int>(LogLevel::INFO), const char *path = nullptr,
                       int rotationFileSize = DEFAULT_ROTATION_FILE_SIZE,
                       int rotationFileCount = DEFAULT_ROTATION_FILE_COUNT);

private:
    Logger() = default;
    std::function<CustomLogFunTy> logFunction_ = nullptr;
    LogLevel displayLogLevel_ = LogLevel::INFO;
};

} // namespace virtrust
