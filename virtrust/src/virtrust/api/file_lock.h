// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

#pragma once

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "virtrust/base/logger.h"

namespace virtrust {

class FileLock {
public:
    FileLock(const char *fileName)
#ifdef VIRTRUST_MOCK
        : fd_(0) // Mock文件描述符，总是成功
    {
        // Fuzz模式下跳过所有文件操作，直接返回成功
        (void)fileName;
    }
#else
        : fd_(open(fileName, O_RDWR | O_CREAT | O_CLOEXEC, LOCK_FILE_PERMISSIONS))
    {
        if (fd_ == -1) {
            VIRTRUST_LOG_ERROR("Failed to open file {}, msg {}", fileName, strerror(errno));
        } else {

            // Force permissions to 600 regardless of umask
            if (fchmod(fd_, 0600) == -1) {
                VIRTRUST_LOG_ERROR("Failed to set permissions for file {}, msg {}", fileName, strerror(errno));
            }

            // Try to acquire the lock
            if (flock(fd_, LOCK_EX) == -1) {
                VIRTRUST_LOG_ERROR("Failed to lock file {}, msg {}", fileName, strerror(errno));
                close(fd_);
                fd_ = -1;
            }
        }
    }
#endif

    ~FileLock()
    {
#ifdef VIRTRUST_MOCK
        // Fuzz模式下不需要做任何清理
        (void)0;
#else
        if (fd_ != -1) {
            flock(fd_, LOCK_UN);
            close(fd_);
            fd_ = -1;
        }
#endif
    }

    bool IsLocked() const
    {
        return fd_ != -1;
    }
    int GetFileDescriptor() const
    {
        return fd_;
    }

private:
    static constexpr mode_t LOCK_FILE_PERMISSIONS = 0666;
    int fd_ = -1;
};

} // namespace virtrust
