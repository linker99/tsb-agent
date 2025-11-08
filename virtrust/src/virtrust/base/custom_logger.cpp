/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include "virtrust/base/custom_logger.h"

#include <string>

// NOTE DO NOT REMOVE this chrono header
#include "spdlog/fmt/bundled/chrono.h"
#include "spdlog/fmt/bundled/core.h"

#include "virtrust/base/log_adapt.h"
#include "virtrust/utils/enum_check.h"

namespace virtrust {
using LogLevelCheck = EnumCheck<LogLevel, LogLevel::TRACE, LogLevel::DEBUG, LogLevel::INFO, LogLevel::WARN,
                                LogLevel::ERROR, LogLevel::CRITICAL>;

namespace {
std::mutex mutex;
constexpr int DEFAULT_STR_TIME_LEN = 24;
constexpr auto DEFAULT_LOG_FUNCTION = [](LogLevel level, std::string_view msg) {
    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    fmt::print("[{} {:%Y-%m-%d %H-%M-%S}] {}\n", LogLevelToStr(level), now, msg);
};
} // namespace

std::string LogLevelToStr(LogLevel level)
{
    switch (level) {
        case LogLevel::TRACE:
            return "TRACE";
        case LogLevel::DEBUG:
            return "DEBUG";
        case LogLevel::INFO:
            return "INFO";
        case LogLevel::WARN:
            return "WARN";
        case LogLevel::ERROR:
            return "ERROR";
        case LogLevel::CRITICAL:
            return "CRITICAL";
        default:
            return "UNKNOWN";
    }
}

Logger *Logger::Instance()
{
    static Logger logger;
    return &logger;
}

void Logger::Log(LogLevel level, std::string_view msg)
{
    if (logFunction_ != nullptr) {
        logFunction_(level, msg);
    } else {
        if (LogAdapt::gSpdLogger != nullptr && LogAdapt::gSpdLogger->spdLogger != nullptr &&
            static_cast<int>(level) >= static_cast<int>(displayLogLevel_)) {
            LogAdapt::gSpdLogger->spdLogger->log(static_cast<spdlog::level::level_enum>(static_cast<int>(level)),
                                                 msg.data());
        }
    }
}

void Logger::SetDisplayLogLevel(LogLevel level)
{
    if (static_cast<int>(level) >= static_cast<int>(LogLevel::UNKNOWN)) {
        fmt::print(stderr, "log level is invalid : {}", static_cast<int>(level));
    }

    if (LogAdapt::gSpdLogger != nullptr && LogAdapt::gSpdLogger->spdLogger != nullptr) {
        LogAdapt::gSpdLogger->spdLogger->set_level(static_cast<spdlog::level::level_enum>(static_cast<int>(level)));
        displayLogLevel_ = level;
    } else {
        fmt::print(stderr, "failed to set log level\n");
    }
}

void Logger::Reset()
{
    logFunction_ = nullptr;
    if (LogAdapt::gSpdLogger != nullptr && LogAdapt::gSpdLogger->spdLogger != nullptr) {
        LogAdapt::gSpdLogger->spdLogger->set_level(
            static_cast<spdlog::level::level_enum>(static_cast<int>(LogLevel::INFO)));
    }
    displayLogLevel_ = LogLevel::INFO;
}

VirtrustRc Logger::InitLog(int logLevel, const char *path, int rotationFileSize, int rotationFileCount)
{

    if (logLevel < static_cast<int>(LogLevel::TRACE) || logLevel > static_cast<int>(LogLevel::CRITICAL)) {
        fmt::print(stderr, "Invalid log level: {}", logLevel);
        return VirtrustRc::ERROR;
    }

    int logType = (path != nullptr) ? FILE_TYPE : STDOUT_TYPE;
    auto rc = LogAdapt::ValidateParams(logType, path, rotationFileSize, rotationFileCount);
    if (rc != VirtrustRc::OK) {
        fmt::print(stderr, "LogAdapt param validation failed, return: {}, msg: {}", static_cast<uint32_t>(rc),
                   LogAdapt::gLastErrorMessage);
        return rc;
    }

    rc = LogAdapt::CreateInstance(logType, logLevel, path, rotationFileSize, rotationFileCount);
    if (rc != VirtrustRc::OK) {
        fmt::print(stderr, "LogAdapt create instance failed, return: {}", static_cast<uint32_t>(rc));
        return rc;
    }

    displayLogLevel_ = static_cast<LogLevel>(logLevel);
    return VirtrustRc::OK;
}

bool Logger::SetCustomLogFunction(const std::function<CustomLogFunTy> &func)
{
    std::lock_guard<std::mutex> lock(mutex);
    if (func == nullptr) {
        DEFAULT_LOG_FUNCTION(LogLevel::ERROR, "Failed to set external log function as log function is nullptr.");
        return false;
    } else {
        logFunction_ = func;
        return true;
    }
}

} // namespace virtrust
