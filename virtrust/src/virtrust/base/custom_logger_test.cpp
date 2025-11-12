/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025.All rights reserved.
 */

#include <thread>

#include "gtest/gtest.h"
#include "spdlog/fmt/fmt.h"

#include "virtrust/base/custom_logger.h"
#include "virtrust/base/logger.h"

namespace virtrust {

TEST(CustomLogger, SetCustomLogFunction)
{
    // Test setting a custom log function
    bool result = Logger::Instance()->SetCustomLogFunction(
        [](LogLevel level, std::string_view msg) { fmt::print("[{}] {}\n", LogLevelToStr(level), msg); });
    EXPECT_TRUE(result);

    // Test setting nullptr function
    result = Logger::Instance()->SetCustomLogFunction(nullptr);
    EXPECT_FALSE(result);

    // Reset the logger
    Logger::Instance()->Reset();
}

TEST(CustomLogger, LogLevelConversion)
{
    // Test conversion of log levels to strings
    EXPECT_EQ(LogLevelToStr(LogLevel::TRACE), "TRACE");
    EXPECT_EQ(LogLevelToStr(LogLevel::DEBUG), "DEBUG");
    EXPECT_EQ(LogLevelToStr(LogLevel::INFO), "INFO");
    EXPECT_EQ(LogLevelToStr(LogLevel::WARN), "WARN");
    EXPECT_EQ(LogLevelToStr(LogLevel::ERROR), "ERROR");
    EXPECT_EQ(LogLevelToStr(LogLevel::CRITICAL), "CRITICAL");
    EXPECT_EQ(LogLevelToStr(LogLevel::UNKNOWN), "UNKNOWN");
}

TEST(CustomLogger, InstanceSingleton)
{
    // Test that Logger follows singleton pattern
    Logger *logger1 = Logger::Instance();
    Logger *logger2 = Logger::Instance();
    EXPECT_EQ(logger1, logger2);
}

TEST(CustomLogger, logWithCustomFunction)
{
    // Test logging with custom function
    std::string captured_log;

    // this log function is actually corrupted when we leave this test
    // Note this is bad practice, do not use capture lambda for log function
    Logger::Instance()->SetCustomLogFunction([&captured_log](LogLevel level, std::string_view msg) {
        captured_log = fmt::format("[{}] {}", LogLevelToStr(level), msg);
    });

    Logger::Instance()->Log(LogLevel::INFO, "Test message");
    EXPECT_FALSE(captured_log.empty());

    // Reset the logger
    Logger::Instance()->Reset();
}

TEST(CustomLogger, logWithoutCustomFunction)
{
    // Test logging without custom function (should use default)
    // This test mainly ensures no crash occurs
    Logger::Instance()->Log(LogLevel::INFO, "Default log message");

    // Test with different log levels
    Logger::Instance()->Log(LogLevel::TRACE, "DTrace message");
    Logger::Instance()->Log(LogLevel::DEBUG, "Debug message");
    Logger::Instance()->Log(LogLevel::WARN, "Warn message");
    Logger::Instance()->Log(LogLevel::ERROR, "Error message");
    Logger::Instance()->Log(LogLevel::CRITICAL, "Critical message");
}

TEST(CustomLogger, ResetFunctionality)
{
    // Test that Reset clears the custom log function
    Logger::Instance()->SetCustomLogFunction(
        [](LogLevel level, std::string_view msg) { fmt::print("[{}] {}\n", LogLevelToStr(level), msg); });

    // Verify custom function is set
    // Node: we can't directly test the function pointer comparison, but we can
    // verify behavior after reset
    Logger::Instance()->Log(LogLevel::INFO, "Message before reset");

    // Reset the logger
    Logger::Instance()->Reset();

    // verify that after reset, we can still log without issues
    Logger::Instance()->Log(LogLevel::INFO, "Message after reset");

    // Reset the logger
    Logger::Instance()->Reset();
}

TEST(CustomLogger, DiaplayLogLevel)
{
    // Test getting and setting display log level
    Logger::Instance()->InitLog();
    auto initial_level = Logger::Instance()->GetDisplayLogLevel();
    EXPECT_EQ(initial_level, LogLevel::INFO);

    // Change display level
    Logger::Instance()->SetDisplayLogLevel(LogLevel::DEBUG);

    auto new_level = Logger::Instance()->GetDisplayLogLevel();
    EXPECT_EQ(new_level, LogLevel::DEBUG);

    // Reset the logger
    Logger::Instance()->Reset();
}

TEST(CustomLogger, ThreadSafety)
{
    // Test that logging is thread-safe
    std::vector<std::thread> threads;
    std::atomic<int> log_count{0};

    // Create multiple threads that log simultaneously
    threads.reserve(10);
    for (int i = 0; i < 10; i++) {
        threads.emplace_back([&log_count]() {
            for (int j = 0; j < 10; j++) {
                Logger::Instance()->Log(LogLevel::INFO, "Thread safety test");
                log_count++;
            }
        });
    }

    // Wait for all threads to complete
    for (auto &t : threads) {
        t.join();
    }

    // Verify all logs were processed
    EXPECT_EQ(log_count.load(), 100);

    // Reset the logger
    Logger::Instance()->Reset();
}
} // namespace virtrust
