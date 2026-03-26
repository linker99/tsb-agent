#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <thread>

namespace virtrust {
class AsyncTimer {
public:
    AsyncTimer() = default;

    ~AsyncTimer()
    {
        Cancel();
    }

    // 启动一个异步计时器，timeout后执行callback
    void Start(std::chrono::microseconds timeout, std::function<void()> callback)
    {
        Cancel(); // 先取消可能存在的旧线程

        canceled_.store(false);
        worker_ = std::thread([=]() {
            auto deadline = std::chrono::steady_clock::now() + timeout;
            while (!canceled_.load()) {
                if (std::chrono::steady_clock::now() >= deadline)
                    break;
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            if (!canceled_.load()) {
                callback();
            }
        });
    }

    // 取消定时器
    void Cancel()
    {
        canceled_.store(true);
        if (worker_.joinable()) {
            if (std::this_thread::get_id() == worker_.get_id()) {
                // 通常调用Cancel的现成!=worker_，除非callback中调用Cancel造成死锁
                worker_.detach();
            } else {
                worker_.join();
            }
        }
    }

private:
    std::thread worker_;
    std::atomic<bool> canceled_{true};
};

} // namespace virtrust
