/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#include <atomic>
#include <chrono>
#include <thread>

#include "gtest/gtest.h"

#include "virtrust/utils/async_timer.h"

namespace virtrust {

class AsyncTimerTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        // Reset counters for each test
        callback_count_ = 0;
        callback_value_ = 0;
    }

    void TearDown() override
    {
        // Give timers time to clean up
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Test helper functions
    void IncrementCallback()
    {
        callback_count_++;
    }

    void SetValueCallback(int value)
    {
        callback_value_ = value;
    }

    static std::atomic<int> callback_count_;
    static std::atomic<int> callback_value_;
};

std::atomic<int> AsyncTimerTest::callback_count_{0};
std::atomic<int> AsyncTimerTest::callback_value_{0};

TEST_F(AsyncTimerTest, Constructor)
{
    AsyncTimer timer;

    // Timer should be constructed successfully
    SUCCEED();
}

TEST_F(AsyncTimerTest, Destructor)
{
    {
        AsyncTimer timer;
        // Timer goes out of scope here
    }

    // Destructor should be called without issues
    SUCCEED();
}

TEST_F(AsyncTimerTest, StartWithShortTimeout)
{
    AsyncTimer timer;

    // Start timer with 100ms timeout
    timer.Start(std::chrono::milliseconds(100), [this]() { IncrementCallback(); });

    // Wait for callback to be called
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(callback_count_.load(), 1);
}

TEST_F(AsyncTimerTest, StartWithMicrosecondTimeout)
{
    AsyncTimer timer;

    // Start timer with 5000 microseconds (5ms)
    timer.Start(std::chrono::microseconds(5000), [this]() { IncrementCallback(); });

    // Wait for callback to be called
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    EXPECT_EQ(callback_count_.load(), 1);
}

TEST_F(AsyncTimerTest, StartWithZeroTimeout)
{
    AsyncTimer timer;

    // Start timer with zero timeout (should trigger quickly)
    timer.Start(std::chrono::microseconds(0), [this]() { IncrementCallback(); });

    // Wait a very short time
    std::this_thread::sleep_for(std::chrono::milliseconds(1));

    EXPECT_EQ(callback_count_.load(), 1);
}

TEST_F(AsyncTimerTest, CancelBeforeTimeout)
{
    AsyncTimer timer;

    // Start timer with 200ms timeout
    timer.Start(std::chrono::milliseconds(200), [this]() { IncrementCallback(); });

    // Cancel after 50ms
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    timer.Cancel();

    // Wait for additional time to ensure callback wasn't called
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_EQ(callback_count_.load(), 0);
}

TEST_F(AsyncTimerTest, CancelImmediatelyAfterStart)
{
    AsyncTimer timer;

    // Start timer and immediately cancel
    timer.Start(std::chrono::milliseconds(100), [this]() { IncrementCallback(); });
    timer.Cancel();

    // Wait for additional time
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(callback_count_.load(), 0);
}

TEST_F(AsyncTimerTest, MultipleStartsShouldCancelPrevious)
{
    AsyncTimer timer;

    // Start first timer
    timer.Start(std::chrono::milliseconds(200), [this]() { callback_value_ = 1; });

    // Start second timer immediately
    timer.Start(std::chrono::milliseconds(100), [this]() { callback_value_ = 2; });

    // Wait for the second timer to trigger
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(callback_value_.load(), 2);

    // Wait longer to ensure first timer doesn't trigger
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_EQ(callback_value_.load(), 2); // Should still be 2, not 1
}

TEST_F(AsyncTimerTest, CancelMultipleTimes)
{
    AsyncTimer timer;

    // Start timer
    timer.Start(std::chrono::milliseconds(100), [this]() { IncrementCallback(); });

    // Cancel multiple times (should not cause issues)
    timer.Cancel();
    timer.Cancel();
    timer.Cancel();

    // Wait to ensure callback wasn't called
    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    EXPECT_EQ(callback_count_.load(), 0);
}

TEST_F(AsyncTimerTest, CancelWithoutStart)
{
    AsyncTimer timer;

    // Cancel without starting timer (should not cause issues)
    timer.Cancel();

    SUCCEED();
}

TEST_F(AsyncTimerTest, RapidStartStopCycles)
{
    AsyncTimer timer;

    // Perform multiple rapid start/stop cycles
    for (int i = 0; i < 10; i++) {
        timer.Start(std::chrono::milliseconds(50), [this]() { IncrementCallback(); });

        // Cancel immediately
        timer.Cancel();

        // Brief pause
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    EXPECT_EQ(callback_count_.load(), 0);
}

TEST_F(AsyncTimerTest, LongTimeout)
{
    AsyncTimer timer;

    // Start timer with longer timeout
    timer.Start(std::chrono::milliseconds(500), [this]() { IncrementCallback(); });

    // Check that callback hasn't been called yet
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(callback_count_.load(), 0);

    // Wait for callback
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_EQ(callback_count_.load(), 1);
}

TEST_F(AsyncTimerTest, MultipleTimersConcurrent)
{
    AsyncTimer timer1, timer2, timer3;

    // Start multiple timers with different delays
    timer1.Start(std::chrono::milliseconds(50), [this]() { callback_value_ += 1; });

    timer2.Start(std::chrono::milliseconds(100), [this]() { callback_value_ += 10; });

    timer3.Start(std::chrono::milliseconds(150), [this]() { callback_value_ += 100; });

    // Wait for all timers to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_EQ(callback_value_.load(), 111); // 1 + 10 + 100
}

TEST_F(AsyncTimerTest, TimerScopeAndDestruction)
{
    std::atomic<int> destruction_count{0};

    {
        AsyncTimer timer;

        // Start timer that might outlive the timer object
        timer.Start(std::chrono::milliseconds(50), [&destruction_count]() { destruction_count++; });

        // Timer goes out of scope here, destructor should be called
    }

    // Wait a bit to see if callback is called
    // Note: This behavior depends on destructor implementation
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // The callback may or may not be called depending on destructor behavior
    // This test mainly ensures destructor doesn't crash
    SUCCEED();
}

TEST_F(AsyncTimerTest, CallbackExceptionHandling)
{
    AsyncTimer timer;

    // Start timer with callback that throws
    timer.Start(std::chrono::milliseconds(50), []() { throw std::runtime_error("Test exception"); });

    // Wait for timer to complete
    // Should not crash the test
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    SUCCEED();
}

TEST_F(AsyncTimerTest, CallbackComplexOperations)
{
    AsyncTimer timer;
    std::vector<int> results;

    // Start timer with complex callback
    timer.Start(std::chrono::milliseconds(50), [&results]() {
        for (int i = 0; i < 10; i++) {
            results.push_back(i * i);
        }
    });

    // Wait for callback to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_EQ(results.size(), 10u);
    EXPECT_EQ(results[0], 0);
    EXPECT_EQ(results[9], 81);
}

TEST_F(AsyncTimerTest, PrecisionTest)
{
    AsyncTimer timer;
    auto start_time = std::chrono::steady_clock::now();
    bool callback_called = false;

    // Start timer with 10ms timeout
    timer.Start(std::chrono::milliseconds(10), [&callback_called]() { callback_called = true; });

    // Wait for callback
    while (!callback_called) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    // Should be approximately 10ms (with some tolerance for scheduling)
    EXPECT_GE(duration.count(), 8);  // At least 8ms
    EXPECT_LE(duration.count(), 50); // At most 50ms (allowing for scheduling delays)

    EXPECT_TRUE(callback_called);
}

} // namespace virtrust