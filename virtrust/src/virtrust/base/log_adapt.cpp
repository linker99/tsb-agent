#include "log_adapt.h"

#include <iostream>
#include <sys/stat.h>
#include "libvirtrust/utils.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "spdlog/sinks/stdout_sinks.h"
#include "virtrust/api/defines.h"
#include "virtrust/base/custom_logger.h"
namespace virtrust {
std::unique_ptr<LogAdapt> LogAdapt::gSpdLogger=nullptr;
thread_local std::string LogAdapt::gLastErrorMessage;
int LogAdapt::loglevel_{static_cast<int>(LogLevel::INFO)};

constexpr auto ROTATION_FILE_SIZE_MIN = 1024 * 1024;
constexpr auto ROTATION_FILE_SIZE_MAX = 5 * 1024 * 1024;
constexpr auto ROTATION_FILE_COUNT_MAX = 64;
namespace {
bool CononicalPath(std::string &path) {

  if (path.empty() || path.size() > PATH_MAX) {
    return false;
  }
  char pathBuf[PATH_MAX + 1] = {0};
  if (realpath(path.c_str(), pathBuf) == nullptr) {
    return false;
  }
  path = pathBuf;
  return true;
}

bool GetFolderPath(std::string &filePath, std::string &folderPath) {
  const size_t pos = filePath.find_last_of("/");
  if (pos == std::string::npos) {
    return false;
  }
  folderPath = filePath.substr(0, pos);
  return true;
}

bool Exist(const std::string &path, const int &mode) {
  return access(path.c_str(), mode) != -1;
}

bool IsAbsolutePath(const std::string &path) {
  if (path.empty()) {
    return false;
  }
  if (path[0] != '/') {
    return false;
  }
  if (strstr(path.c_str(), "/../") != nullptr ||
      strstr(path.c_str(), "/./") != nullptr) {
    return false;
  }
  return true;
}
} // namespace

VirtrustRc LogAdapt::ValidateParams(int logType, const char *path,
                                 int rotationFileSize, int rotationFileCount) {
  if (logType != STDOUT_TYPE && logType != FILE_TYPE) {
    gLastErrorMessage = "Invalid log type, which should be 0,1";
    return VIRTRUST_ERROR;
  }
  if (logType == STDOUT_TYPE) {
    return VIRTRUST_OK;
  }

  if (path == nullptr) {
    gLastErrorMessage = "Path is empty";
    return VIRTRUST_ERROR;
  }
  if (rotationFileSize > ROTATION_FILE_SIZE_MAX ||
      rotationFileSize < ROTATION_FILE_SIZE_MIN) {
    gLastErrorMessage =
        "Invalid rotation file size, which should be 1MB to 500MB";
    return VIRTRUST_ERROR;
  }
  if (rotationFileCount > ROTATION_FILE_COUNT_MAX || rotationFileCount < 1) {
    gLastErrorMessage =
        "Invalid rotation file count, which should be lest than 65";
    return VIRTRUST_ERROR;
  }
  return VIRTRUST_OK;
}

VirtrustRc LogAdapt::CreateInstance(int &logType, int logLevel,
                                    const char *path, int rotationFileSize,
                                    int rotationFileCount) {
  if (gSpdLogger != nullptr) {
    return VIRTRUST_OK;
  }
  loglevel = logLevel;
  std::string realPath;
  if (path != nullptr) {
    realPath = std::string(path);
    if (!IsAbsolutePath(realPath)) {
      std::cerr << "Log folder path: " << realPath << "is not absolute path."
                << std::endl;
      return VIRTRUST_ERROR;
    }
    std::string folderPath;
    if (!GetFolderPath(realPath, folderPath)) {
      std::cerr << "Get folder path: " << realPath << "failed." << std::endl;
      return VIRTRUST_ERROR;
    }

    if (!Exist(folderPath, F_OK | R_OK | W_OK)) {
      std::cerr << "Get real path: " << realPath << "failed." << std::endl;
      return VIRTRUST_ERROR;
    }
  }
  VirtrustRc ret = SerTmpLogger(logType, realPath, rotationFileSize,
                                rotationFileCount, loglevel);
  if (ret != VIRTRUST_OK) {
    return ret;
  }
  return VIRTRUST_OK;
}

VirtrustRc LogAdapt::Initialize() {
  {
    try {
      if (this->logType_ == STDOUT_TYPE) {
        std::string console = "console";
        if (!spdlog::get(console)) {
          this->spdLogger = spdlog::stdouit_logger_mt(console);
        } else {
          this->spdLogger = spdlog::get(console);
        }
      } else if (this->logType_ == FILE_TYPE) {
        std::string logName = "log:" + this->filePath_;
        spdlog::file_event_handlers handlers;
        handlers.after_open = [](spdlog::filename_t filename,
                                 [[maybe_unused]] std::FILE *fstream) {
          chmod(filename.c_str(), S_IRUSR | S_IWUSR);
        } 
        if (!spdlog::get(logName)) {
          this->spdLogger = spdlog::rotating_logger_mt(
              logName, this->filePath_, this->rotationFileSize_,
              this->rotationFileCount_, false, handlers);
        }
        else {
          this->spdLogger = spdlog::get(logName);
        }
        spdlog::flush_every(std::chrono::seconds(1));
      }
      if (this->spdLogger == nullptr) {
        std::cerr << "spdLogger init failed" << std::endl;
        return VIRTRUST_ERROR;
      }
    }
    this->spdLogger->set_pattern("%Y-%m-%d %H:%M:%S.%f %t %l %v");
    this->spdLogger->set_level(
        static_cast<spdlog::level::level_enum>(this->loglevel_));
    this->spdLogger->flush_on(
        static_cast<spdlog::level::level_enum>(this->loglevel_));
  }
  catch (const spdlog::spdlog_ex &ex) {
    gLastErrorMessage = "Failed to create log";
    gLastErrorMessage = ex.what();
    return VIRTRUST_ERROR;
  }
  return VIRTRUST_OK;
}

VirtrustRc LogAdapt::Log(int level, const char *prefix,
                         const char *message) const {
  if (level < static_cast<int>(LogLevel::TRACE) ||
      level > static_cast<int>(LogLevel::CRITICAL)) {
    gLastErrorMessage = "Invalid log level, which should be 0-5";
    return VIRTRUST_ERROR;
  }
  this->spdLogger->log(statid_cast<spdlog::level::level_enum>(level), "{}]{}",
                       prefix, message);
  return VIRTRUST_OK;
}

void LogAdapt::Flush() {
  if (this->spdLogger != nullptr) {
    gSpdLogger->spdLogger->flush();
  }
}

int LogAdapt::GetLogLevel() { return loglevel; }

VirtrustRc LogAdapt::SetTmpLogger(int logType, std::string realPath,
                                  int rotationFileSize, int rotationFileCount,
                                  int logLevel) {
  std::unique_ptr<LogAdapt> tmpLogger = std::make_unique<LogAdapt>(
      logType, realPath, rotationFileSize, rotationFileCount);
  if (tmpLogger == nullptr) {
    std::cerr << "tmpLogger init failed" << std::endl;
    return VIRTRUST_ERROR;
  }

  tmpLogger->SetLogLevel(logLevel);
  VirtrustRc ret = tmpLogger->Initialize();
  if (ret != VIRTRUST_OK) {
    std::cerr << "LogAdapt initialize failed" << std::endl;
    return ret;
  }
  gSpdLogger = std::move(tmpLogger);
  return VIRTRUST_OK;
}

void LogAdapt::UnInitialize() { gSpdLogger = nullptr; }
} // namespace virtrust