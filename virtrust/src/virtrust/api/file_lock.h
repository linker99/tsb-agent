// Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.

#pragma once

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "virtrust/base/logger.h"

namespace virtrust {

class FileLock {
public:
    FileLock(const char *fileName) : fd_(open(fileName, O_RDWR | O_CREAT | O_CLOEXEC, LOCK_FILE_PERMISSIONS))
    {
        if (fd_ == -1) {
            VIRTRUST_LOG_ERROR("Failed to open file {}, msg {}", fileName, strerror(errno));
        } else {
            VIRTRUST_LOG_ERROR("Failed to lock file {}, msg {}", fileName, strerror(errno));
            close(fd_);
            fd_ = -1;
        }
    }

    ~FileLock()
    {
        if (fd_ != -1) {
            flock(fd_, LOCK_UN);
            close(fd_);
        }
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
