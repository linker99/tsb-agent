#ifndef TSB_AGENT_FILE_LOCK_H
#define TSB_AGENT_FILE_LOCK_H

#include "virtrust/base/logger.h"
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>


namespace virtrust {

class FileLock {
public:
  FileLock(const char *fileName)
      : fd_(open(fileName, O_RDWR | O_CREAT | O_CLOEXEC,
                 LOCK_FILE_PERMISSIONS)) {
    if (fd_ == -1) {
      VIRTRUST_LOG_ERROR("Failed to open file {}, msg {}", fileName,
                         strerror(errno));
    } else {
      VIRTRUST_LOG_ERROR("Failed to lock file {}, msg {}", fileName,
                         strerror(errno));
      close(fd_);
      fd_ = -1;
    }

    ~FileLock() {
      if (fd_ != -1) {
        flock(fd_, LOCK_UN);
        close(fd_);
      }
    }

    bool isLocked() const { return fd_ != -1; }
    int GetFileDescriptor() const { return fd_; }

  private:
    static constexpr mode_t LOCK_FILE_PERMISSIONS = 0644;
    int fd_ = -1;
  };
}

} // namespace virtrust

#endif // TSB_AGENT_FILE_LOCK_H
